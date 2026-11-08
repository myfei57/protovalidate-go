// Copyright 2023-2026 Buf Technologies, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package protovalidate

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	pvcel "buf.build/go/protovalidate/cel"
	"cel.dev/cel-go/cel"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/apipb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
	"google.golang.org/protobuf/types/known/sourcecontextpb"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/typepb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Sentinel errors reported by the descriptor bundle manager. Callers should
// use [errors.Is] to test for them.
//
//nolint:gochecknoglobals // sentinel errors are intentionally package-level
var (
	// ErrNoBundlePublished is returned when validation is attempted before any
	// generation has been published.
	ErrNoBundlePublished = errors.New(
		"protovalidate: no descriptor bundle generation has been published")

	// ErrGenerationConflict is returned by CompareAndPublish when the current
	// generation is no longer the expected one. The published generation is not
	// modified.
	ErrGenerationConflict = errors.New(
		"protovalidate: descriptor bundle generation conflict")

	// ErrIncompatibleDescriptor is returned when a validated message's
	// descriptor shares a full name with a bundle type but is not the exact
	// descriptor object owned by the bundle. Such messages are never read by
	// full-name reflection; they must either be rejected or explicitly
	// re-decoded through the wire format when WireRedecode is enabled.
	ErrIncompatibleDescriptor = errors.New(
		"protovalidate: message descriptor is incompatible with the descriptor bundle")

	// ErrMessageNotInBundle is returned when the validated message's type is
	// not present in the active bundle generation.
	ErrMessageNotInBundle = errors.New(
		"protovalidate: message type is not part of the descriptor bundle")
)

// DefaultAllowedDependencies lists the well-known schema files that may be
// used to satisfy imports absent from a [BundleConfig.FileDescriptorSet] when
// no explicit allowlist is provided. Only these exact paths can ever be
// resolved outside the set; [protoregistry.GlobalFiles] and
// [protoregistry.GlobalTypes] are never consulted, so locally registered
// same-name user schemas cannot leak into a bundle.
//
//nolint:gochecknoglobals // immutable default allowlist
var DefaultAllowedDependencies = []string{
	"buf/validate/validate.proto",
	"google/protobuf/any.proto",
	"google/protobuf/api.proto",
	"google/protobuf/descriptor.proto",
	"google/protobuf/duration.proto",
	"google/protobuf/empty.proto",
	"google/protobuf/field_mask.proto",
	"google/protobuf/source_context.proto",
	"google/protobuf/struct.proto",
	"google/protobuf/timestamp.proto",
	"google/protobuf/type.proto",
	"google/protobuf/wrappers.proto",
}

// wellKnownDependencyFiles maps the permitted external dependency paths to
// the descriptors compiled into this binary. Every entry is part of the
// protobuf/protovalidate standard library, whose content is fixed by the
// runtime version; the identity of each file actually used is recorded in the
// bundle.
//
//nolint:gochecknoglobals // immutable standard-library descriptor table
var wellKnownDependencyFiles = map[string]protoreflect.FileDescriptor{
	"buf/validate/validate.proto":          validate.File_buf_validate_validate_proto,
	"google/protobuf/any.proto":            anypb.File_google_protobuf_any_proto,
	"google/protobuf/api.proto":            apipb.File_google_protobuf_api_proto,
	"google/protobuf/descriptor.proto":     descriptorpb.File_google_protobuf_descriptor_proto,
	"google/protobuf/duration.proto":       durationpb.File_google_protobuf_duration_proto,
	"google/protobuf/empty.proto":          emptypb.File_google_protobuf_empty_proto,
	"google/protobuf/field_mask.proto":     fieldmaskpb.File_google_protobuf_field_mask_proto,
	"google/protobuf/source_context.proto": sourcecontextpb.File_google_protobuf_source_context_proto,
	"google/protobuf/struct.proto":         structpb.File_google_protobuf_struct_proto,
	"google/protobuf/timestamp.proto":      timestamppb.File_google_protobuf_timestamp_proto,
	"google/protobuf/type.proto":           typepb.File_google_protobuf_type_proto,
	"google/protobuf/wrappers.proto":       wrapperspb.File_google_protobuf_wrappers_proto,
}

// BundleIdentity is the content identity of a built [DescriptorBundle].
type BundleIdentity struct {
	// Sum is a SHA-256 digest over every descriptor byte in the set (ordered
	// by file path), the explicitly requested root messages and the build
	// flags. Two builds with identical inputs and flags share the same Sum.
	Sum [32]byte

	// Files records the SHA-256 identity of every file contributing to the
	// bundle, including explicitly permitted well-known dependencies resolved
	// outside the descriptor set.
	Files map[string][32]byte
}

// BundleGeneration is an opaque handle identifying one published generation
// of a [DescriptorBundleManager].
type BundleGeneration struct {
	id       uint64
	identity BundleIdentity
}

// ID returns the monotonically increasing, process-unique generation number.
func (g BundleGeneration) ID() uint64 { return g.id }

// Identity returns the content identity of the generation.
func (g BundleGeneration) Identity() BundleIdentity { return g.identity }

// BundleConfig configures an offline, self-contained descriptor bundle build.
type BundleConfig struct {
	// FileDescriptorSet is the complete set of file descriptors the bundle is
	// built from. It must contain every user schema and every non-allowed
	// import; nothing is downloaded or looked up from the process globals.
	FileDescriptorSet *descriptorpb.FileDescriptorSet

	// RootMessages lists the fully-qualified names of the messages the bundle
	// must validate. Each root and its full transitive message closure is
	// resolved and pre-warmed before a generation can be published.
	RootMessages []protoreflect.FullName

	// AllowedDependencies enumerates file paths permitted to be resolved from
	// the runtime's compiled-in well-known schemas when absent from
	// FileDescriptorSet. nil selects DefaultAllowedDependencies; an empty
	// (non-nil) slice forbids all external dependencies.
	AllowedDependencies []string

	// AllowUnknownFields, when true, ignores rule extensions unknown to this
	// runtime instead of failing the build. Defaults to failing, so that
	// missing rules are never silently skipped.
	AllowUnknownFields bool

	// DisableNativeRules forces all rule evaluation through CEL, matching
	// [WithDisableNativeRules].
	DisableNativeRules bool

	// WireRedecode enables re-decoding messages whose descriptor is not the
	// bundle's own descriptor object through the wire format into bundle
	// dynamic messages. When false (the default), such messages are rejected
	// with ErrIncompatibleDescriptor.
	WireRedecode bool
}

// DescriptorBundle is an immutable, fully validated bundle produced by
// BuildDescriptorBundle. It is not usable for validation until it is
// published atomically through a [DescriptorBundleManager].
type DescriptorBundle struct {
	identity       BundleIdentity
	files          *protoregistry.Files
	extensionTypes *protoregistry.Types
	validator      *validator
	builder        *builder
	roots          []protoreflect.MessageDescriptor
	wireRedecode   bool
}

// Identity reports the content identity computed for the bundle.
func (b *DescriptorBundle) Identity() BundleIdentity { return b.identity }

// BuildDescriptorBundle constructs a read-only, laziness-free descriptor
// bundle entirely offline from the provided complete descriptor set and
// explicit root messages. Missing imports, duplicate file names or symbol
// names, unknown rule extensions and CEL compilation failures are all reported
// as errors before a bundle can be returned and published. A failed build has
// no effect on any manager.
func BuildDescriptorBundle(config BundleConfig) (*DescriptorBundle, error) {
	if config.FileDescriptorSet == nil || len(config.FileDescriptorSet.File) == 0 {
		return nil, errors.New(
			"protovalidate: BundleConfig.FileDescriptorSet must not be empty")
	}
	if len(config.RootMessages) == 0 {
		return nil, errors.New(
			"protovalidate: BundleConfig.RootMessages must list at least one root message")
	}

	allowed := map[string]protoreflect.FileDescriptor{}
	switch {
	case config.AllowedDependencies == nil:
		for path, desc := range wellKnownDependencyFiles {
			allowed[path] = desc
		}
	default:
		for _, path := range config.AllowedDependencies {
			desc, ok := wellKnownDependencyFiles[path]
			if !ok {
				return nil, fmt.Errorf(
					"protovalidate: allowed dependency %q is not a recognized well-known schema",
					path)
			}
			allowed[path] = desc
		}
	}

	fdByName := make(map[string]*descriptorpb.FileDescriptorProto,
		len(config.FileDescriptorSet.File))
	for _, fd := range config.FileDescriptorSet.File {
		path := fd.GetName()
		if path == "" {
			return nil, errors.New(
				"protovalidate: descriptor set contains a file with an empty name")
		}
		if _, exists := fdByName[path]; exists {
			return nil, fmt.Errorf(
				"protovalidate: duplicate file name %q in descriptor set", path)
		}
		fdByName[path] = fd
	}

	// Resolve every declared import against (set ∪ allowlist) up front so a
	// missing dependency is reported with a precise error instead of being
	// silently picked up from somewhere else.
	for path, fd := range fdByName {
		for _, dep := range fd.Dependency {
			if _, inSet := fdByName[dep]; inSet {
				continue
			}
			if _, permitted := allowed[dep]; !permitted {
				return nil, fmt.Errorf(
					"protovalidate: unresolved import %q required by %q: "+
						"not present in the descriptor set and not in the allowed well-known dependency list",
					dep, path)
			}
		}
	}

	// Only well-known files actually imported by the set are registered,
	// together with their own allowlisted transitive imports. GlobalFiles is
	// never consulted, and the identity of every used dependency is recorded.
	usedWellKnownPaths := map[string]struct{}{}
	var markWellKnown func(path string)
	markWellKnown = func(path string) {
		if _, done := usedWellKnownPaths[path]; done {
			return
		}
		if _, inSet := fdByName[path]; inSet {
			return // a file shipped in the set is built from the set itself
		}
		desc, permitted := allowed[path]
		if !permitted {
			return
		}
		usedWellKnownPaths[path] = struct{}{}
		imports := desc.Imports()
		for i := range imports.Len() {
			markWellKnown(imports.Get(i).Path())
		}
	}
	for _, fd := range fdByName {
		for _, dep := range fd.Dependency {
			if _, inSet := fdByName[dep]; !inSet {
				markWellKnown(dep)
			}
		}
	}

	// An isolated file registry: only descriptor-set files and the well-known
	// dependencies actually referenced by them are ever registered here.
	files := new(protoregistry.Files)
	usedWellKnown := make(map[string]protoreflect.FileDescriptor,
		len(usedWellKnownPaths))
	var registerWellKnown func(path string) error
	registerWellKnown = func(path string) error {
		if _, done := usedWellKnown[path]; done {
			return nil
		}
		if _, inSet := fdByName[path]; inSet {
			return nil // provided by the set; it is built and registered below
		}
		desc := allowed[path]
		imports := desc.Imports()
		for i := range imports.Len() {
			if _, allowedDep := allowed[imports.Get(i).Path()]; allowedDep {
				if err := registerWellKnown(imports.Get(i).Path()); err != nil {
					return err
				}
			}
		}
		if err := files.RegisterFile(desc); err != nil {
			return fmt.Errorf(
				"protovalidate: failed to register allowed dependency %q: %w",
				path, err)
		}
		usedWellKnown[path] = desc
		return nil
	}
	for path := range usedWellKnownPaths {
		if _, inSet := fdByName[path]; inSet {
			continue // a set-provided file always shadows the runtime copy
		}
		if err := registerWellKnown(path); err != nil {
			return nil, err
		}
	}

	// Register descriptor-set files in topological order.
	visiting := map[string]bool{}
	visited := map[string]bool{}
	var register func(path string) error
	register = func(path string) error {
		if visited[path] {
			return nil
		}
		if visiting[path] {
			return fmt.Errorf(
				"protovalidate: import cycle detected at %q", path)
		}
		fd, inSet := fdByName[path]
		if !inSet {
			return nil // allowed well-known dependency, already registered
		}
		visiting[path] = true
		for _, dep := range fd.Dependency {
			if err := register(dep); err != nil {
				return err
			}
		}
		delete(visiting, path)
		built, err := protodesc.FileOptions{}.New(fd, files)
		if err != nil {
			return fmt.Errorf(
				"protovalidate: failed to build descriptor for %q: %w",
				path, err)
		}
		if err := files.RegisterFile(built); err != nil {
			return fmt.Errorf(
				"protovalidate: failed to register descriptor for %q: %w",
				path, err)
		}
		visited[path] = true
		return nil
	}
	for path := range fdByName {
		if err := register(path); err != nil {
			return nil, err
		}
	}

	// Resolve the explicit root messages.
	rootSet := map[protoreflect.FullName]struct{}{}
	roots := make([]protoreflect.MessageDescriptor, 0, len(config.RootMessages))
	for _, name := range config.RootMessages {
		if !name.IsValid() {
			return nil, fmt.Errorf(
				"protovalidate: invalid root message full name %q", string(name))
		}
		if _, duplicated := rootSet[name]; duplicated {
			return nil, fmt.Errorf(
				"protovalidate: root message %q is listed more than once", name)
		}
		rootSet[name] = struct{}{}
		desc, err := files.FindDescriptorByName(name)
		if err != nil {
			return nil, fmt.Errorf(
				"protovalidate: root message %q could not be resolved: %w", name, err)
		}
		messageDesc, ok := desc.(protoreflect.MessageDescriptor)
		if !ok {
			return nil, fmt.Errorf(
				"protovalidate: root %q is a %T, not a message descriptor",
				name, desc)
		}
		roots = append(roots, messageDesc)
	}

	// A private extension resolver containing only the protovalidate rule
	// extensions. GlobalTypes is never used, so local extension registrations
	// cannot leak in.
	extensionTypes := new(protoregistry.Types)
	for _, extension := range []protoreflect.ExtensionType{
		validate.E_Field,
		validate.E_Message,
		validate.E_Oneof,
		validate.E_Predefined,
	} {
		if err := extensionTypes.RegisterExtension(extension); err != nil {
			return nil, fmt.Errorf(
				"protovalidate: failed to register rule extension %s: %w",
				extension.TypeDescriptor().FullName(), err)
		}
	}

	// Each generation gets its own CEL type registry, environment and builder
	// caches, so evaluators compiled for one descriptor object can never be
	// reused for another generation's same-named but incompatible type.
	celTypeRegistry, err := newRegistry()
	if err != nil {
		return nil, fmt.Errorf(
			"failed to construct CEL type registry: %w", err)
	}
	env, err := cel.NewEnv(
		cel.CustomTypeProvider(celTypeRegistry),
		cel.CustomTypeAdapter(celTypeRegistry),
		cel.Lib(pvcel.NewLibrary()),
	)
	if err != nil {
		return nil, fmt.Errorf(
			"failed to construct CEL environment: %w", err)
	}

	// Lazy building is disabled and all roots (with their transitive closure)
	// are seeded up front, so the resulting validator is read-only and no rule
	// is first discovered during a live request.
	bldr := newBuilder(
		env,
		true, // disableLazy
		extensionTypes,
		config.AllowUnknownFields,
		config.DisableNativeRules,
		roots...,
	)

	if err := prewarmBundle(bldr, roots); err != nil {
		return nil, err
	}

	identity, err := computeBundleIdentity(
		fdByName, usedWellKnown, config, roots)
	if err != nil {
		return nil, err
	}

	return &DescriptorBundle{
		identity:       identity,
		files:          files,
		extensionTypes: extensionTypes,
		validator: &validator{
			builder: bldr,
			cfg: &validationConfig{
				filter: nopFilter{},
				nowFn:  timestamppb.Now,
			},
		},
		builder:      bldr,
		roots:        roots,
		wireRedecode: config.WireRedecode,
	}, nil
}

// prewarmBundle verifies that every message reachable from the roots has a
// cached evaluator and that none of the cached evaluators carries a
// compilation error (unknown rule extension, failed CEL compile, invalid rule
// shape, ...). Evaluating an empty instance surfaces every cached
// CompilationError regardless of input; validation and runtime errors on the
// empty message are ignored, as they are request-time concerns rather than
// build failures.
func prewarmBundle(bldr *builder, roots []protoreflect.MessageDescriptor) error {
	closure := collectMessageClosure(roots)
	warmCfg := &validationConfig{
		filter: nopFilter{},
		nowFn:  timestamppb.Now,
	}
	var buildErrs []error
	for _, desc := range closure {
		eval := bldr.Load(desc)
		if _, ok := eval.(unknownMessage); ok {
			buildErrs = append(buildErrs, fmt.Errorf(
				"protovalidate: no evaluator was pre-warmed for message %q",
				desc.FullName()))
			continue
		}
		err := eval.EvaluateMessage(
			dynamicpb.NewMessage(desc), warmCfg)
		var compilationErr *CompilationError
		if errors.As(err, &compilationErr) {
			buildErrs = append(buildErrs, fmt.Errorf(
				"protovalidate: rule compilation failed for message %q: %w",
				desc.FullName(), compilationErr))
		}
	}
	return errors.Join(buildErrs...)
}

// collectMessageClosure returns every message descriptor reachable from the
// roots through message, group, repeated-item and map-value fields.
func collectMessageClosure(
	roots []protoreflect.MessageDescriptor,
) []protoreflect.MessageDescriptor {
	seen := map[protoreflect.MessageDescriptor]struct{}{}
	out := make([]protoreflect.MessageDescriptor, 0)
	var walk func(protoreflect.MessageDescriptor)
	walk = func(desc protoreflect.MessageDescriptor) {
		if _, ok := seen[desc]; ok {
			return
		}
		seen[desc] = struct{}{}
		out = append(out, desc)
		fields := desc.Fields()
		for i := range fields.Len() {
			field := fields.Get(i)
			switch {
			case field.IsMap():
				if key := field.MapKey(); isMessageField(key) {
					walk(key.Message())
				}
				if value := field.MapValue(); isMessageField(value) {
					walk(value.Message())
				}
			case isMessageField(field):
				walk(field.Message())
			}
		}
	}
	for _, root := range roots {
		walk(root)
	}
	return out
}

// computeBundleIdentity derives the deterministic content identity of a build,
// including the per-file identities of used well-known dependencies.
func computeBundleIdentity(
	fdByName map[string]*descriptorpb.FileDescriptorProto,
	usedWellKnown map[string]protoreflect.FileDescriptor,
	config BundleConfig,
	roots []protoreflect.MessageDescriptor,
) (BundleIdentity, error) {
	marshalOpts := proto.MarshalOptions{Deterministic: true}
	fileIdentities := make(map[string][32]byte, len(fdByName)+len(usedWellKnown))
	hasher := sha256.New()

	record := func(path string, raw []byte) {
		fileIdentities[path] = sha256.Sum256(raw)
		fmt.Fprintf(hasher, "file:%s:%d:", path, len(raw))
		_, _ = hasher.Write(raw)
	}

	setPaths := make([]string, 0, len(fdByName))
	for path := range fdByName {
		setPaths = append(setPaths, path)
	}
	slices.Sort(setPaths)
	for _, path := range setPaths {
		raw, err := marshalOpts.Marshal(fdByName[path])
		if err != nil {
			return BundleIdentity{}, fmt.Errorf(
				"protovalidate: failed to encode %q for identity: %w", path, err)
		}
		record(path, raw)
	}

	wktPaths := make([]string, 0, len(usedWellKnown))
	for path := range usedWellKnown {
		wktPaths = append(wktPaths, path)
	}
	slices.Sort(wktPaths)
	for _, path := range wktPaths {
		raw, err := marshalOpts.Marshal(
			protodesc.ToFileDescriptorProto(usedWellKnown[path]))
		if err != nil {
			return BundleIdentity{}, fmt.Errorf(
				"protovalidate: failed to encode dependency %q for identity: %w",
				path, err)
		}
		record(path, raw)
	}

	rootNames := make([]string, 0, len(roots))
	for _, root := range roots {
		rootNames = append(rootNames, string(root.FullName()))
	}
	slices.Sort(rootNames)
	for _, name := range rootNames {
		fmt.Fprintf(hasher, "root:%s:", name)
	}
	fmt.Fprintf(hasher, "flags:%t:%t:%t",
		config.AllowUnknownFields,
		config.DisableNativeRules,
		config.WireRedecode)
	allowed := slices.Clone(config.AllowedDependencies)
	slices.Sort(allowed)
	for _, path := range allowed {
		fmt.Fprintf(hasher, "allow:%s:", path)
	}

	var sum [32]byte
	copy(sum[:], hasher.Sum(nil))
	return BundleIdentity{Sum: sum, Files: fileIdentities}, nil
}

// bundleGeneration is one immutable, published bundle. Its descriptor objects,
// CEL environment and evaluator caches are never shared with another
// generation.
type bundleGeneration struct {
	id             uint64
	identity       BundleIdentity
	files          *protoregistry.Files
	extensionTypes *protoregistry.Types
	validator      *validator
	builder        *builder
	wireRedecode   bool

	// users counts in-flight validations and pinned snapshots. Old
	// generations with zero users can be reclaimed by the manager.
	users atomic.Int64
}

// DescriptorBundleManager hot-swaps fully validated descriptor bundles by
// content-addressed generations. Publish is atomic; every validation pins the
// generation it starts with and never observes a mid-flight swap.
type DescriptorBundleManager struct {
	mtx      sync.Mutex
	nextID   uint64
	current  atomic.Pointer[bundleGeneration]
	retained map[uint64]*bundleGeneration
}

// NewDescriptorBundleManager creates an empty manager. Validation returns
// ErrNoBundlePublished until the first generation is published.
func NewDescriptorBundleManager() *DescriptorBundleManager {
	return &DescriptorBundleManager{
		retained: map[uint64]*bundleGeneration{},
	}
}

// CurrentGeneration returns the generation currently serving validation. The
// boolean is false before the first successful publish.
func (m *DescriptorBundleManager) CurrentGeneration() (BundleGeneration, bool) {
	current := m.current.Load()
	if current == nil {
		return BundleGeneration{}, false
	}
	return current.handle(), true
}

// Publish atomically installs a newly built bundle as the next generation.
// Publishing a bundle whose content identity matches the current generation is
// a no-op and returns the current generation unchanged.
func (m *DescriptorBundleManager) Publish(
	bundle *DescriptorBundle,
) (BundleGeneration, error) {
	if bundle == nil {
		return BundleGeneration{}, errors.New(
			"protovalidate: cannot publish a nil descriptor bundle")
	}
	m.mtx.Lock()
	defer m.mtx.Unlock()
	return m.publishLocked(bundle)
}

// CompareAndPublish installs bundle only when the generation currently
// serving validation is still expected. On mismatch ErrGenerationConflict is
// returned and the live generation is left untouched.
func (m *DescriptorBundleManager) CompareAndPublish(
	expected BundleGeneration,
	bundle *DescriptorBundle,
) (BundleGeneration, error) {
	if bundle == nil {
		return BundleGeneration{}, errors.New(
			"protovalidate: cannot publish a nil descriptor bundle")
	}
	m.mtx.Lock()
	defer m.mtx.Unlock()
	current := m.current.Load()
	if current == nil || current.id != expected.id {
		actual := uint64(0)
		if current != nil {
			actual = current.id
		}
		return BundleGeneration{}, fmt.Errorf(
			"%w: expected generation %d, current generation is %d",
			ErrGenerationConflict, expected.id, actual)
	}
	return m.publishLocked(bundle)
}

func (m *DescriptorBundleManager) publishLocked(
	bundle *DescriptorBundle,
) (BundleGeneration, error) {
	current := m.current.Load()
	if current != nil && current.identity.Sum == bundle.identity.Sum {
		return current.handle(), nil
	}

	generation := &bundleGeneration{
		id:             m.nextID,
		identity:       bundle.identity,
		files:          bundle.files,
		extensionTypes: bundle.extensionTypes,
		validator:      bundle.validator,
		builder:        bundle.builder,
		wireRedecode:   bundle.wireRedecode,
	}
	m.nextID++

	if current != nil && current.users.Load() > 0 {
		// Keep the previous generation reachable until its in-flight
		// validations and pinned snapshots complete.
		m.retained[current.id] = current
	}
	m.current.Store(generation)
	return generation.handle(), nil
}

// Validate validates msg against the generation published at call entry. The
// same generation serves message-type resolution and every nested evaluation,
// even if another goroutine swaps generations concurrently.
func (m *DescriptorBundleManager) Validate(
	msg proto.Message,
	options ...ValidationOption,
) error {
	generation := m.current.Load()
	if generation == nil {
		return ErrNoBundlePublished
	}
	generation.users.Add(1)
	defer m.release(generation)
	return generation.validate(msg, options...)
}

// Snapshot returns a read-only Validator pinned to the current generation. The
// snapshot keeps validating that exact generation after later publishes, so a
// request that spans a swap completes against a stable schema.
func (m *DescriptorBundleManager) Snapshot() (BundleSnapshot, error) {
	generation := m.current.Load()
	if generation == nil {
		return nil, ErrNoBundlePublished
	}
	return &bundleSnapshot{
		manager:    m,
		generation: generation,
	}, nil
}

// release drops one user reference and reclaims generations that no longer
// serve traffic and are no longer current.
func (m *DescriptorBundleManager) release(generation *bundleGeneration) {
	if generation.users.Add(-1) != 0 {
		return
	}
	m.mtx.Lock()
	defer m.mtx.Unlock()
	if current := m.current.Load(); current != nil && current.id == generation.id {
		return // the serving generation is always retained while current
	}
	delete(m.retained, generation.id)
}

// BundleSnapshot is a [Validator] pinned to one generation.
type BundleSnapshot interface {
	Validator

	// Generation returns the generation this snapshot is pinned to.
	Generation() BundleGeneration
}

type bundleSnapshot struct {
	manager    *DescriptorBundleManager
	generation *bundleGeneration
}

func (s *bundleSnapshot) Validate(
	msg proto.Message,
	options ...ValidationOption,
) error {
	s.generation.users.Add(1)
	defer s.manager.release(s.generation)
	return s.generation.validate(msg, options...)
}

func (s *bundleSnapshot) Generation() BundleGeneration {
	return s.generation.handle()
}

func (g *bundleGeneration) handle() BundleGeneration {
	return BundleGeneration{id: g.id, identity: g.identity}
}

// validate runs one validation entirely against this generation's own
// descriptors and evaluator cache.
func (g *bundleGeneration) validate(
	msg proto.Message,
	options ...ValidationOption,
) error {
	if msg == nil {
		return nil
	}
	reflect := msg.ProtoReflect()
	descriptor := reflect.Descriptor()

	resolved, err := g.files.FindDescriptorByName(descriptor.FullName())
	if err != nil {
		return fmt.Errorf("%w: %s: %w",
			ErrMessageNotInBundle, descriptor.FullName(), err)
	}
	bundleDescriptor, ok := resolved.(protoreflect.MessageDescriptor)
	if !ok {
		return fmt.Errorf("%w: %s resolves to %T, not a message",
			ErrMessageNotInBundle, descriptor.FullName(), resolved)
	}

	target := msg
	if bundleDescriptor != descriptor {
		// Never read an incompatible message by full-name reflection. Either
		// reject it outright or explicitly re-decode it through the wire.
		if !g.wireRedecode {
			return fmt.Errorf("%w: message %s was built from a different "+
				"descriptor object than generation %d",
				ErrIncompatibleDescriptor, descriptor.FullName(), g.id)
		}
		raw, err := proto.Marshal(msg)
		if err != nil {
			return fmt.Errorf("protovalidate: wire re-decode marshal failed for %s: %w",
				descriptor.FullName(), err)
		}
		dynamic := dynamicpb.NewMessage(bundleDescriptor)
		if err := (proto.UnmarshalOptions{
			Resolver: g.extensionTypes,
		}).Unmarshal(raw, dynamic); err != nil {
			return fmt.Errorf("protovalidate: wire re-decode unmarshal failed for %s: %w",
				descriptor.FullName(), err)
		}
		target = dynamic
	}
	return g.validator.Validate(target, options...)
}
