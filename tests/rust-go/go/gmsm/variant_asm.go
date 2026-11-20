//go:build !purego

// Copyright 2026 RatioLabs (https://www.ratiolabs.eu). Licensed under the Apache License, Version 2.0.

package main

// Built without the purego tag: gmsm uses its assembly (on amd64, AVX2 if the CPU has it).
const variant = "assembly"
