load("//tools:defs.bzl", "go_library")

package(
    default_applicable_licenses = ["//:license"],
    default_visibility = ["//pkg/sentry:internal"],
    licenses = ["notice"],
)

go_library(
    name = "unique_name_landlock",
    srcs = [
        "domain.go",
        "ruleset.go",
    ],
    deps = [
        "//pkg/abi/linux",
        "//pkg/context",
        "//pkg/errors/linuxerr",
        "//pkg/sentry/kernel/auth",
        "//pkg/sentry/vfs",
        "//pkg/sync",
    ],
)
