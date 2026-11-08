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
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"buf.build/gen/go/bufbuild/protovalidate/protocolbuffers/go/buf/validate"
	examplev1 "buf.build/go/protovalidate/internal/gen/tests/example/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

func bundleScalarField(
	name string, number int32,
	typ descriptorpb.FieldDescriptorProto_Type,
	rules *validate.FieldRules,
) *descriptorpb.FieldDescriptorProto {
	field := &descriptorpb.FieldDescriptorProto{
		Name:   proto.String(name),
		Number: proto.Int32(number),
		Type:   typ.Enum(),
		Label:  descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
	}
	if rules != nil {
		field.Options = fieldOpts(rules)
	}
	return field
}

func bundleMessageField(
	name string, number int32, typeName string,
	rules *validate.FieldRules,
) *descriptorpb.FieldDescriptorProto {
	field := bundleScalarField(
		name, number, descriptorpb.FieldDescriptorProto_TYPE_MESSAGE, rules)
	field.TypeName = proto.String(typeName)
	return field
}

func bundleFile(
	path, pkg string,
	messages []*descriptorpb.DescriptorProto,
	deps ...string,
) *descriptorpb.FileDescriptorProto {
	if len(deps) == 0 {
		deps = []string{"buf/validate/validate.proto"}
	}
	return &descriptorpb.FileDescriptorProto{
		Name:        proto.String(path),
		Package:     proto.String(pkg),
		Syntax:      proto.String("proto3"),
		Dependency:  deps,
		MessageType: messages,
	}
}

func bundleSet(files ...*descriptorpb.FileDescriptorProto) *descriptorpb.FileDescriptorSet {
	return &descriptorpb.FileDescriptorSet{File: files}
}

func messageOptions(rules *validate.MessageRules) *descriptorpb.MessageOptions {
	options := &descriptorpb.MessageOptions{}
	proto.SetExtension(options, validate.E_Message, rules)
	return options
}

func mustBuildBundle(
	t testing.TB, config BundleConfig,
) *DescriptorBundle {
	t.Helper()
	bundle, err := BuildDescriptorBundle(config)
	require.NoError(t, err)
	require.NotNil(t, bundle)
	return bundle
}

func mustFindMessage(
	t testing.TB, files *protoregistry.Files, name protoreflect.FullName,
) protoreflect.MessageDescriptor {
	t.Helper()
	desc, err := files.FindDescriptorByName(name)
	require.NoError(t, err)
	messageDesc, ok := desc.(protoreflect.MessageDescriptor)
	require.True(t, ok, "%s is not a message", name)
	return messageDesc
}

func newDynamicMessage(
	desc protoreflect.MessageDescriptor,
	field string, value protoreflect.Value,
) *dynamicpb.Message {
	msg := dynamicpb.NewMessage(desc)
	if field != "" {
		msg.Set(desc.Fields().ByName(protoreflect.Name(field)), value)
	}
	return msg
}

// standaloneMessageType builds a message type in a fresh, private descriptor
// graph. Even when its full name matches a bundle type, the descriptor object
// is distinct from the bundle's.
func standaloneMessageType(
	t testing.TB, path, pkg, name string,
	fields ...*descriptorpb.FieldDescriptorProto,
) protoreflect.MessageType {
	t.Helper()
	registry := new(protoregistry.Files)
	require.NoError(t, registry.RegisterFile(
		validate.File_buf_validate_validate_proto))
	file := bundleFile(path, pkg, []*descriptorpb.DescriptorProto{{
		Name:  proto.String(name),
		Field: fields,
	}})
	fd, err := protodesc.FileOptions{}.New(file, registry)
	require.NoError(t, err)
	return dynamicpb.NewMessageType(
		fd.Messages().ByName(protoreflect.Name(name)))
}

func widgetFDS(path string, field *descriptorpb.FieldDescriptorProto) *descriptorpb.FileDescriptorSet {
	return bundleSet(bundleFile(path, "test.hot", []*descriptorpb.DescriptorProto{{
		Name:  proto.String("Widget"),
		Field: []*descriptorpb.FieldDescriptorProto{field},
	}}))
}

// ---------------------------------------------------------------------------
// Build, identity and basic validation
// ---------------------------------------------------------------------------

func TestDescriptorBundle_BuildAndValidate(t *testing.T) {
	t.Parallel()
	fds := widgetFDS("test/bundle/basic.proto", bundleScalarField(
		"value", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING,
		validate.FieldRules_builder{
			String: validate.StringRules_builder{MinLen: proto.Uint64(3)}.Build(),
		}.Build(),
	))
	root := protoreflect.FullName("test.hot.Widget")
	config := BundleConfig{
		FileDescriptorSet: fds,
		RootMessages:      []protoreflect.FullName{root},
	}

	bundle := mustBuildBundle(t, config)
	assert.Contains(t, bundle.Identity().Files, "test/bundle/basic.proto")
	assert.Contains(t, bundle.Identity().Files,
		"buf/validate/validate.proto",
		"allowed well-known dependency identity must be recorded")
	assert.NotContains(t, bundle.Identity().Files,
		"google/protobuf/wrappers.proto",
		"well-known files that are not imported must not be recorded")

	// Identity is deterministic for identical inputs.
	rebuilt := mustBuildBundle(t, config)
	assert.Equal(t, bundle.Identity().Sum, rebuilt.Identity().Sum)

	manager := NewDescriptorBundleManager()
	_, ok := manager.CurrentGeneration()
	assert.False(t, ok)

	generation, err := manager.Publish(bundle)
	require.NoError(t, err)
	current, ok := manager.CurrentGeneration()
	require.True(t, ok)
	assert.Equal(t, generation, current)

	gen := manager.current.Load()
	desc := mustFindMessage(t, gen.files, root)
	require.NoError(t, manager.Validate(
		newDynamicMessage(desc, "value", protoreflect.ValueOfString("abc"))))
	err = manager.Validate(
		newDynamicMessage(desc, "value", protoreflect.ValueOfString("ab")))
	var validationErr *ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "string.min_len",
		validationErr.Violations[0].Proto.GetRuleId())

	// Validation before any publish fails explicitly.
	emptyManager := NewDescriptorBundleManager()
	assert.ErrorIs(t, emptyManager.Validate(
		dynamicpb.NewMessage(desc)), ErrNoBundlePublished)
	_, err = emptyManager.Snapshot()
	assert.ErrorIs(t, err, ErrNoBundlePublished)
}

func TestDescriptorBundle_RejectsEmptyInputs(t *testing.T) {
	t.Parallel()
	_, err := BuildDescriptorBundle(BundleConfig{})
	assert.Error(t, err)

	fds := widgetFDS("test/bundle/empty.proto", bundleScalarField(
		"value", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, nil))
	_, err = BuildDescriptorBundle(BundleConfig{FileDescriptorSet: fds})
	assert.Error(t, err)

	_, err = BuildDescriptorBundle(BundleConfig{
		FileDescriptorSet: fds,
		RootMessages:      []protoreflect.FullName{"test.hot.Missing"},
	})
	assert.Error(t, err)

	_, err = BuildDescriptorBundle(BundleConfig{
		FileDescriptorSet: fds,
		RootMessages: []protoreflect.FullName{
			"test.hot.Widget", "test.hot.Widget",
		},
	})
	assert.ErrorContains(t, err, "listed more than once")
}

// ---------------------------------------------------------------------------
// Two generations sharing a full name with different fields and rules
// ---------------------------------------------------------------------------

func TestDescriptorBundle_TwoVersionsSameFullName(t *testing.T) {
	t.Parallel()
	v1FDS := widgetFDS("test/hot/widget_v1.proto", bundleScalarField(
		"value", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING,
		validate.FieldRules_builder{
			String: validate.StringRules_builder{MinLen: proto.Uint64(3)}.Build(),
		}.Build(),
	))
	v2FDS := widgetFDS("test/hot/widget_v2.proto", bundleScalarField(
		"value", 1, descriptorpb.FieldDescriptorProto_TYPE_INT32,
		validate.FieldRules_builder{
			Int32: validate.Int32Rules_builder{Gt: proto.Int32(10)}.Build(),
		}.Build(),
	))
	root := []protoreflect.FullName{"test.hot.Widget"}

	manager := NewDescriptorBundleManager()
	gen1, err := manager.Publish(mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: v1FDS, RootMessages: root,
	}))
	require.NoError(t, err)

	oldSnapshot, err := manager.Snapshot()
	require.NoError(t, err)
	oldGen := manager.current.Load()
	v1Desc := mustFindMessage(t, oldGen.files, "test.hot.Widget")

	gen2, err := manager.Publish(mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: v2FDS, RootMessages: root,
	}))
	require.NoError(t, err)
	assert.NotEqual(t, gen1.ID(), gen2.ID())
	assert.NotEqual(t, gen1.Identity().Sum, gen2.Identity().Sum)

	newGen := manager.current.Load()
	v2Desc := mustFindMessage(t, newGen.files, "test.hot.Widget")
	assert.NotSame(t, v1Desc, v2Desc,
		"each generation must own independent descriptor objects")
	assert.NotSame(t, oldGen.builder, newGen.builder,
		"each generation must own an independent build cache")
	cacheV1 := *oldGen.builder.cache.Load()
	cacheV2 := *newGen.builder.cache.Load()
	assert.Contains(t, cacheV1, v1Desc)
	assert.Contains(t, cacheV2, v2Desc)
	assert.NotContains(t, cacheV2, v1Desc,
		"an old evaluator must never be reused for the new version")

	// The current generation enforces v2 (int32 gt 10).
	require.NoError(t, manager.Validate(
		newDynamicMessage(v2Desc, "value", protoreflect.ValueOfInt32(11))))
	err = manager.Validate(
		newDynamicMessage(v2Desc, "value", protoreflect.ValueOfInt32(10)))
	var validationErr *ValidationError
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "int32.gt", validationErr.Violations[0].Proto.GetRuleId())

	// A v1 message must not be reflected into the v2 bundle by full name.
	err = manager.Validate(
		newDynamicMessage(v1Desc, "value", protoreflect.ValueOfString("hello")))
	assert.ErrorIs(t, err, ErrIncompatibleDescriptor)

	// The pinned old snapshot still completes against v1 rules after the swap.
	assert.Equal(t, gen1.ID(), oldSnapshot.Generation().ID())
	require.NoError(t, oldSnapshot.Validate(
		newDynamicMessage(v1Desc, "value", protoreflect.ValueOfString("abc"))))
	err = oldSnapshot.Validate(
		newDynamicMessage(v1Desc, "value", protoreflect.ValueOfString("ab")))
	require.ErrorAs(t, err, &validationErr)
	assert.Equal(t, "string.min_len",
		validationErr.Violations[0].Proto.GetRuleId())
}

func TestDescriptorBundle_SnapshotStableAcrossSwaps(t *testing.T) {
	t.Parallel()
	manager := NewDescriptorBundleManager()
	root := []protoreflect.FullName{"test.hot.Widget"}

	first := mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: widgetFDS("test/hot/s0.proto", bundleScalarField(
			"value", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING,
			validate.FieldRules_builder{
				String: validate.StringRules_builder{MinLen: proto.Uint64(2)}.Build(),
			}.Build())),
		RootMessages: root,
	})
	gen1, err := manager.Publish(first)
	require.NoError(t, err)
	snapshot, err := manager.Snapshot()
	require.NoError(t, err)

	for i := 3; i < 6; i++ {
		_, err = manager.Publish(mustBuildBundle(t, BundleConfig{
			FileDescriptorSet: widgetFDS(
				fmt.Sprintf("test/hot/s%d.proto", i), bundleScalarField(
					"value", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING,
					validate.FieldRules_builder{
						String: validate.StringRules_builder{
							MinLen: proto.Uint64(uint64(i)),
						}.Build(),
					}.Build())),
			RootMessages: root,
		}))
		require.NoError(t, err)
	}
	current, ok := manager.CurrentGeneration()
	require.True(t, ok)
	assert.NotEqual(t, gen1.ID(), current.ID())
	assert.Equal(t, gen1.ID(), snapshot.Generation().ID())

	// The snapshot owns its generation pointer directly, so it stays usable
	// even though the manager has moved on to newer generations.
	pinned := snapshot.(*bundleSnapshot).generation
	oldDesc := mustFindMessage(t, pinned.files, "test.hot.Widget")
	// Two characters pass min_len=2 even though the current generation needs
	// more, proving the snapshot is pinned to the old evaluators.
	require.NoError(t, snapshot.Validate(
		newDynamicMessage(oldDesc, "value", protoreflect.ValueOfString("ab"))))
	err = snapshot.Validate(
		newDynamicMessage(oldDesc, "value", protoreflect.ValueOfString("a")))
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// Concurrent publish and validation
// ---------------------------------------------------------------------------

func TestDescriptorBundle_ConcurrentPublishAndValidate(t *testing.T) {
	t.Parallel()
	manager := NewDescriptorBundleManager()
	root := []protoreflect.FullName{"test.hot.Widget"}

	_, err := manager.Publish(mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: widgetFDS("test/hot/c0.proto", bundleScalarField(
			"value", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING,
			validate.FieldRules_builder{
				String: validate.StringRules_builder{MinLen: proto.Uint64(1)}.Build(),
			}.Build())),
		RootMessages: root,
	}))
	require.NoError(t, err)

	const publishers = 12
	const validators = 8
	const iterations = 40
	var failure atomic.Bool
	var wg sync.WaitGroup

	for p := range publishers {
		wg.Add(1)
		go func(minLen uint64) {
			defer wg.Done()
			bundle, buildErr := BuildDescriptorBundle(BundleConfig{
				FileDescriptorSet: widgetFDS(
					fmt.Sprintf("test/hot/c_%d.proto", minLen), bundleScalarField(
						"value", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING,
						validate.FieldRules_builder{
							String: validate.StringRules_builder{
								MinLen: proto.Uint64(minLen),
							}.Build(),
						}.Build())),
				RootMessages: root,
			})
			if buildErr != nil {
				failure.Store(true)
				assert.NoError(t, buildErr)
				return
			}
			if _, publishErr := manager.Publish(bundle); publishErr != nil {
				failure.Store(true)
				assert.NoError(t, publishErr)
			}
		}(uint64(p + 2))
	}

	for range validators {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iterations {
				snapshot, snapshotErr := manager.Snapshot()
				if !assert.NoError(t, snapshotErr) {
					failure.Store(true)
					return
				}
				pinned := snapshot.(*bundleSnapshot).generation
				resolved, lookupErr := pinned.files.FindDescriptorByName(
					"test.hot.Widget")
				if !assert.NoError(t, lookupErr) {
					failure.Store(true)
					return
				}
				desc, ok := resolved.(protoreflect.MessageDescriptor)
				if !assert.True(t, ok, "root must be a message descriptor") {
					failure.Store(true)
					return
				}

				// Messages built from the snapshot's own descriptor must
				// always validate against that exact generation.
				good := newDynamicMessage(desc, "value",
					protoreflect.ValueOfString(strings.Repeat("x", publishers+5)))
				if err := snapshot.Validate(good); err != nil {
					failure.Store(true)
					assert.NoError(t, err)
				}
				bad := newDynamicMessage(desc, "value",
					protoreflect.ValueOfString(""))
				if err := snapshot.Validate(bad); err == nil {
					failure.Store(true)
					assert.Error(t, err, "empty value must violate min_len")
				}
			}
		}()
	}
	wg.Wait()
	assert.False(t, failure.Load(), "concurrent publish/validate failed")

	current, ok := manager.CurrentGeneration()
	require.True(t, ok)
	assert.Equal(t, manager.current.Load().id, current.ID())
}

// ---------------------------------------------------------------------------
// Missing imports and GlobalFiles isolation
// ---------------------------------------------------------------------------

func TestDescriptorBundle_MissingImport(t *testing.T) {
	t.Parallel()
	fds := bundleSet(bundleFile(
		"test/missing/user.proto", "test.missing",
		[]*descriptorpb.DescriptorProto{{Name: proto.String("User")}},
		"buf/validate/validate.proto",
		"test/missing/not_provided.proto",
	))
	_, err := BuildDescriptorBundle(BundleConfig{
		FileDescriptorSet: fds,
		RootMessages:      []protoreflect.FullName{"test.missing.User"},
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "unresolved import")
	assert.ErrorContains(t, err, "test/missing/not_provided.proto")
}

func TestDescriptorBundle_DoesNotFallBackToGlobalFiles(t *testing.T) {
	t.Parallel()
	// google/protobuf/struct.proto is registered in protoregistry.GlobalFiles
	// by the linked runtime. It is deliberately excluded from the bundle's
	// allowlist: an isolated build must report the unresolved import instead
	// of silently picking the global file up by path.
	const globalOnlyPath = "google/protobuf/struct.proto"
	_, err := protoregistry.GlobalFiles.FindFileByPath(globalOnlyPath)
	require.NoError(t, err, "test precondition: %q must exist globally",
		globalOnlyPath)

	fds := bundleSet(bundleFile(
		"test/bundle/global_shadow/user.proto",
		"test.bundle.global_shadow",
		[]*descriptorpb.DescriptorProto{{Name: proto.String("User")}},
		"buf/validate/validate.proto",
		globalOnlyPath,
	))
	_, err = BuildDescriptorBundle(BundleConfig{
		FileDescriptorSet: fds,
		RootMessages: []protoreflect.FullName{
			"test.bundle.global_shadow.User",
		},
		AllowedDependencies: []string{
			"buf/validate/validate.proto",
		},
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "unresolved import")
	assert.ErrorContains(t, err, globalOnlyPath)

	manager := NewDescriptorBundleManager()
	_, ok := manager.CurrentGeneration()
	assert.False(t, ok, "a failed build must never publish a generation")
}

// ---------------------------------------------------------------------------
// Duplicate file names and symbol conflicts
// ---------------------------------------------------------------------------

func TestDescriptorBundle_DuplicateFileName(t *testing.T) {
	t.Parallel()
	file := bundleFile("test/dup/same.proto", "test.dup",
		[]*descriptorpb.DescriptorProto{{Name: proto.String("One")}})
	_, err := BuildDescriptorBundle(BundleConfig{
		FileDescriptorSet: bundleSet(file, proto.Clone(file).(*descriptorpb.FileDescriptorProto)),
		RootMessages:      []protoreflect.FullName{"test.dup.One"},
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "duplicate file name")
}

func TestDescriptorBundle_DuplicateSymbol(t *testing.T) {
	t.Parallel()
	first := bundleFile("test/dup/a.proto", "test.dup",
		[]*descriptorpb.DescriptorProto{{Name: proto.String("Collision")}})
	second := bundleFile("test/dup/b.proto", "test.dup",
		[]*descriptorpb.DescriptorProto{{Name: proto.String("Collision")}})
	_, err := BuildDescriptorBundle(BundleConfig{
		FileDescriptorSet: bundleSet(first, second),
		RootMessages:      []protoreflect.FullName{"test.dup.Collision"},
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "name conflict")
}

// ---------------------------------------------------------------------------
// Unknown rule extensions
// ---------------------------------------------------------------------------

func TestDescriptorBundle_UnknownRuleExtension(t *testing.T) {
	t.Parallel()
	enumRules := validate.EnumRules_builder{Const: proto.Int32(1)}.Build()
	proto.SetExtension(enumRules, examplev1.E_EnumForbidden, []int32{99})
	proto.SetExtension(enumRules, examplev1.E_InOrZero, true)
	raw, err := proto.Marshal(enumRules)
	require.NoError(t, err)
	unknownRules := &validate.EnumRules{}
	require.NoError(t, proto.UnmarshalOptions{
		Resolver: new(protoregistry.Types),
	}.Unmarshal(raw, unknownRules))
	require.NotEmpty(t, unknownRules.ProtoReflect().GetUnknown())

	file := bundleFile("test/unknown/holder.proto", "test.unknown",
		[]*descriptorpb.DescriptorProto{{
			Name: proto.String("Holder"),
			Field: []*descriptorpb.FieldDescriptorProto{{
				Name:     proto.String("status"),
				Number:   proto.Int32(1),
				Type:     descriptorpb.FieldDescriptorProto_TYPE_ENUM.Enum(),
				TypeName: proto.String(".test.unknown.Status"),
				Label:    descriptorpb.FieldDescriptorProto_LABEL_OPTIONAL.Enum(),
				Options: fieldOpts(validate.FieldRules_builder{
					Enum: unknownRules,
				}.Build()),
			}},
		}})
	file.EnumType = []*descriptorpb.EnumDescriptorProto{{
		Name: proto.String("Status"),
		Value: []*descriptorpb.EnumValueDescriptorProto{
			{Name: proto.String("STATUS_UNSPECIFIED"), Number: proto.Int32(0)},
			{Name: proto.String("STATUS_ACTIVE"), Number: proto.Int32(1)},
		},
	}}
	config := BundleConfig{
		FileDescriptorSet: bundleSet(file),
		RootMessages:      []protoreflect.FullName{"test.unknown.Holder"},
	}

	manager := NewDescriptorBundleManager()
	good, err := manager.Publish(mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: widgetFDS("test/unknown/seed.proto", bundleScalarField(
			"value", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, nil)),
		RootMessages: []protoreflect.FullName{"test.hot.Widget"},
	}))
	require.NoError(t, err)

	_, err = BuildDescriptorBundle(config)
	require.Error(t, err)
	var compilationErr *CompilationError
	require.ErrorAs(t, err, &compilationErr)
	assert.ErrorContains(t, err, "unknown rules")
	current, ok := manager.CurrentGeneration()
	require.True(t, ok)
	assert.Equal(t, good.ID(), current.ID(),
		"a failed build must not change the current generation")

	// Allowing unknown fields makes the same set buildable.
	allowed := mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: bundleSet(proto.Clone(file).(*descriptorpb.FileDescriptorProto)),
		RootMessages:      []protoreflect.FullName{"test.unknown.Holder"},
		AllowUnknownFields: true,
	})
	gen, err := manager.Publish(allowed)
	require.NoError(t, err)
	assert.NotEqual(t, good.ID(), gen.ID())
}

// ---------------------------------------------------------------------------
// CEL compilation failures
// ---------------------------------------------------------------------------

func TestDescriptorBundle_CELCompileFailure(t *testing.T) {
	t.Parallel()
	file := bundleFile("test/cel/bad.proto", "test.cel",
		[]*descriptorpb.DescriptorProto{{
			Name: proto.String("CelMsg"),
			Options: messageOptions(validate.MessageRules_builder{
				Cel: []*validate.Rule{validate.Rule_builder{
					Id:         proto.String("bad_expr"),
					Expression: proto.String("this =="),
				}.Build()},
			}.Build()),
		}})
	config := BundleConfig{
		FileDescriptorSet: bundleSet(file),
		RootMessages:      []protoreflect.FullName{"test.cel.CelMsg"},
	}
	_, err := BuildDescriptorBundle(config)
	require.Error(t, err)
	var compilationErr *CompilationError
	require.ErrorAs(t, err, &compilationErr)
	assert.ErrorContains(t, err, "failed to compile expression")

	manager := NewDescriptorBundleManager()
	seed, err := manager.Publish(mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: widgetFDS("test/cel/seed.proto", bundleScalarField(
			"value", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING,
			validate.FieldRules_builder{
				String: validate.StringRules_builder{MinLen: proto.Uint64(1)}.Build(),
			}.Build())),
		RootMessages: []protoreflect.FullName{"test.hot.Widget"},
	}))
	require.NoError(t, err)

	_, err = BuildDescriptorBundle(config)
	require.Error(t, err)
	current, ok := manager.CurrentGeneration()
	require.True(t, ok)
	assert.Equal(t, seed.ID(), current.ID())

	// The old generation still serves requests correctly.
	desc := mustFindMessage(t, manager.current.Load().files, "test.hot.Widget")
	require.NoError(t, manager.Validate(
		newDynamicMessage(desc, "value", protoreflect.ValueOfString("ok"))))
}

// ---------------------------------------------------------------------------
// Compare-and-publish semantics
// ---------------------------------------------------------------------------

func TestDescriptorBundle_CompareAndPublish(t *testing.T) {
	t.Parallel()
	manager := NewDescriptorBundleManager()
	root := []protoreflect.FullName{"test.hot.Widget"}
	first := mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: widgetFDS("test/cas/v1.proto", bundleScalarField(
			"value", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, nil)),
		RootMessages: root,
	})

	_, err := manager.CompareAndPublish(
		BundleGeneration{id: 1}, first)
	assert.ErrorIs(t, err, ErrGenerationConflict)

	gen1, err := manager.Publish(first)
	require.NoError(t, err)

	_, err = manager.Publish(nil)
	assert.Error(t, err)
	_, err = manager.CompareAndPublish(gen1, nil)
	assert.Error(t, err)

	// Stale expected generation: no overwrite.
	second := mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: widgetFDS("test/cas/v2.proto", bundleScalarField(
			"value", 1, descriptorpb.FieldDescriptorProto_TYPE_INT32, nil)),
		RootMessages: root,
	})
	_, err = manager.CompareAndPublish(
		BundleGeneration{id: gen1.ID() + 99}, second)
	assert.ErrorIs(t, err, ErrGenerationConflict)
	current, _ := manager.CurrentGeneration()
	assert.Equal(t, gen1.ID(), current.ID())

	// Correct expected generation: swap succeeds.
	gen2, err := manager.CompareAndPublish(gen1, second)
	require.NoError(t, err)
	assert.NotEqual(t, gen1.ID(), gen2.ID())

	// Identical content is a no-op and keeps the generation id.
	again, err := manager.Publish(mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: widgetFDS("test/cas/v2.proto", bundleScalarField(
			"value", 1, descriptorpb.FieldDescriptorProto_TYPE_INT32, nil)),
		RootMessages: root,
	}))
	require.NoError(t, err)
	assert.Equal(t, gen2.ID(), again.ID())
}

// ---------------------------------------------------------------------------
// Reclamation of unused old generations
// ---------------------------------------------------------------------------

func TestDescriptorBundle_ReclaimOldGenerations(t *testing.T) {
	t.Parallel()
	manager := NewDescriptorBundleManager()
	root := []protoreflect.FullName{"test.hot.Widget"}

	gen1, err := manager.Publish(mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: widgetFDS("test/reclaim/v1.proto", bundleScalarField(
			"value", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, nil)),
		RootMessages: root,
	}))
	require.NoError(t, err)
	old := manager.current.Load()

	// Simulate an in-flight validation pinned to gen1 while a new generation
	// is published: the old generation must stay reachable for its users.
	old.users.Add(1)
	_, err = manager.Publish(mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: widgetFDS("test/reclaim/v2.proto", bundleScalarField(
			"value", 1, descriptorpb.FieldDescriptorProto_TYPE_BOOL, nil)),
		RootMessages: root,
	}))
	require.NoError(t, err)
	assert.Same(t, old, manager.retained[gen1.ID()])

	// Once the last user releases it, the old generation is reclaimed.
	manager.release(old)
	assert.NotContains(t, manager.retained, gen1.ID())

	// A subsequent swap with no users on the outgoing generation needs no
	// retention entry at all.
	gen3, err := manager.Publish(mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: widgetFDS("test/reclaim/v3.proto", bundleScalarField(
			"value", 1, descriptorpb.FieldDescriptorProto_TYPE_INT32, nil)),
		RootMessages: root,
	}))
	require.NoError(t, err)
	current, ok := manager.CurrentGeneration()
	require.True(t, ok)
	assert.Equal(t, gen3.ID(), current.ID())

	// A snapshot taken before a swap still works once the old generation has
	// been dropped from the retention map, because it owns the pointer.
	snapshot, err := manager.Snapshot()
	require.NoError(t, err)
	pinned := snapshot.(*bundleSnapshot).generation
	pinnedDesc := mustFindMessage(t, pinned.files, "test.hot.Widget")
	_, err = manager.Publish(mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: widgetFDS("test/reclaim/v4.proto", bundleScalarField(
			"value", 1, descriptorpb.FieldDescriptorProto_TYPE_STRING, nil)),
		RootMessages: root,
	}))
	require.NoError(t, err)
	assert.NotContains(t, manager.retained, pinned.id)
	require.NoError(t, snapshot.Validate(
		dynamicpb.NewMessage(pinnedDesc)))
}

// ---------------------------------------------------------------------------
// Descriptor incompatibility and explicit wire re-decoding
// ---------------------------------------------------------------------------

func TestDescriptorBundle_IncompatibleDescriptorAndWireRedecode(t *testing.T) {
	t.Parallel()
	external := standaloneMessageType(t,
		"test/wire/external.proto", "test.wire", "Msg",
		bundleScalarField("a", 1,
			descriptorpb.FieldDescriptorProto_TYPE_STRING, nil))

	bundleFileWithB := func(ruleOnB *validate.FieldRules) *descriptorpb.FileDescriptorSet {
		return bundleSet(bundleFile("test/wire/bundle.proto", "test.wire",
			[]*descriptorpb.DescriptorProto{{
				Name: proto.String("Msg"),
				Field: []*descriptorpb.FieldDescriptorProto{
					bundleScalarField("a", 1,
						descriptorpb.FieldDescriptorProto_TYPE_STRING, nil),
					bundleScalarField("b", 2,
						descriptorpb.FieldDescriptorProto_TYPE_STRING, ruleOnB),
				},
			}}))
	}
	root := []protoreflect.FullName{"test.wire.Msg"}

	// Strict mode rejects the foreign descriptor object.
	strict := NewDescriptorBundleManager()
	_, err := strict.Publish(mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: bundleFileWithB(nil),
		RootMessages:      root,
	}))
	require.NoError(t, err)
	externalMsg := dynamicpb.NewMessage(external.Descriptor())
	externalMsg.Set(external.Descriptor().Fields().ByName("a"),
		protoreflect.ValueOfString("hello"))
	err = strict.Validate(externalMsg)
	assert.ErrorIs(t, err, ErrIncompatibleDescriptor)

	// A type unknown to the bundle is rejected distinctly.
	other := standaloneMessageType(t,
		"test/wire/other.proto", "test.wire", "Other",
		bundleScalarField("x", 1,
			descriptorpb.FieldDescriptorProto_TYPE_STRING, nil))
	err = strict.Validate(dynamicpb.NewMessage(other.Descriptor()))
	assert.ErrorIs(t, err, ErrMessageNotInBundle)

	// Wire mode re-decodes into the bundle descriptor and runs bundle rules.
	wireManager := NewDescriptorBundleManager()
	_, err = wireManager.Publish(mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: bundleFileWithB(validate.FieldRules_builder{
			String: validate.StringRules_builder{MinLen: proto.Uint64(2)}.Build(),
		}.Build()),
		RootMessages: root,
		WireRedecode: true,
	}))
	require.NoError(t, err)
	err = wireManager.Validate(externalMsg)
	var validationErr *ValidationError
	require.ErrorAs(t, err, &validationErr,
		"re-decoded message must be checked against bundle-only field b")
	assert.Equal(t, "string.min_len",
		validationErr.Violations[0].Proto.GetRuleId())

	// Without the rule on b, re-decoding a compatible wire layout succeeds.
	relaxed := NewDescriptorBundleManager()
	_, err = relaxed.Publish(mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: bundleFileWithB(nil),
		RootMessages:      root,
		WireRedecode: true,
	}))
	require.NoError(t, err)
	assert.NoError(t, relaxed.Validate(externalMsg))
}

// ---------------------------------------------------------------------------
// Well-known dependency allowlist and identity
// ---------------------------------------------------------------------------

func TestDescriptorBundle_WellKnownDependencies(t *testing.T) {
	t.Parallel()
	eventFile := bundleFile(
		"test/wkt/event.proto", "test.wkt",
		[]*descriptorpb.DescriptorProto{{
			Name: proto.String("Event"),
			Field: []*descriptorpb.FieldDescriptorProto{
				bundleMessageField("ts", 1,
					".google.protobuf.Timestamp", nil),
			},
		}},
		"buf/validate/validate.proto",
		"google/protobuf/timestamp.proto",
	)
	root := []protoreflect.FullName{"test.wkt.Event"}

	bundle := mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: bundleSet(eventFile),
		RootMessages:      root,
	})
	assert.Contains(t, bundle.Identity().Files,
		"google/protobuf/timestamp.proto")
	assert.Contains(t, bundle.Identity().Files,
		"buf/validate/validate.proto")

	// Restricting the allowlist makes the same missing import fatal.
	_, err := BuildDescriptorBundle(BundleConfig{
		FileDescriptorSet: bundleSet(proto.Clone(eventFile).(*descriptorpb.FileDescriptorProto)),
		RootMessages:      root,
		AllowedDependencies: []string{
			"buf/validate/validate.proto",
		},
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "unresolved import")

	// An unrecognized allowlist entry is rejected up front.
	_, err = BuildDescriptorBundle(BundleConfig{
		FileDescriptorSet: bundleSet(eventFile),
		RootMessages:      root,
		AllowedDependencies: []string{
			"buf/validate/validate.proto",
			"test/wkt/not_well_known.proto",
		},
	})
	require.Error(t, err)
	assert.ErrorContains(t, err, "not a recognized well-known schema")

	// Shipping the WKT inside the set makes the build self-contained and the
	// recorded identity matches the runtime descriptor bytes.
	selfContained := bundleSet(
		protodesc.ToFileDescriptorProto(
			timestamppb.File_google_protobuf_timestamp_proto),
		proto.Clone(eventFile).(*descriptorpb.FileDescriptorProto),
	)
	inline := mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: selfContained,
		RootMessages:      root,
	})
	raw, err := (proto.MarshalOptions{Deterministic: true}).Marshal(
		protodesc.ToFileDescriptorProto(
			timestamppb.File_google_protobuf_timestamp_proto))
	require.NoError(t, err)
	assert.Equal(t, sha256.Sum256(raw),
		inline.Identity().Files["google/protobuf/timestamp.proto"])
}

// ---------------------------------------------------------------------------
// Eager pre-warming and disabled lazy loading
// ---------------------------------------------------------------------------

func TestDescriptorBundle_PrewarmsTransitiveClosure(t *testing.T) {
	t.Parallel()
	fds := bundleSet(bundleFile("test/prewarm/root.proto", "test.prewarm",
		[]*descriptorpb.DescriptorProto{
			{
				Name: proto.String("Root"),
				Field: []*descriptorpb.FieldDescriptorProto{
					bundleMessageField("child", 1,
						".test.prewarm.Child", nil),
				},
			},
			{
				Name: proto.String("Child"),
				Field: []*descriptorpb.FieldDescriptorProto{
					bundleScalarField("value", 1,
						descriptorpb.FieldDescriptorProto_TYPE_STRING,
						validate.FieldRules_builder{
							String: validate.StringRules_builder{
								MinLen: proto.Uint64(2),
							}.Build(),
						}.Build()),
				},
			},
		}))
	bundle := mustBuildBundle(t, BundleConfig{
		FileDescriptorSet: fds,
		RootMessages:      []protoreflect.FullName{"test.prewarm.Root"},
	})
	cache := *bundle.builder.cache.Load()
	rootDesc := mustFindMessage(t, bundle.files, "test.prewarm.Root")
	childDesc := mustFindMessage(t, bundle.files, "test.prewarm.Child")
	assert.Contains(t, cache, rootDesc)
	assert.Contains(t, cache, childDesc,
		"transitive messages must be warmed before publishing")

	// Lazy loading is disabled: an unseen descriptor gets an erroring
	// evaluator rather than triggering a build on the first request.
	foreign := standaloneMessageType(t,
		"test/prewarm/foreign.proto", "test.prewarm", "Foreign",
		bundleScalarField("v", 1,
			descriptorpb.FieldDescriptorProto_TYPE_STRING, nil))
	eval := bundle.builder.Load(foreign.Descriptor())
	_, ok := eval.(unknownMessage)
	assert.True(t, ok)
}
