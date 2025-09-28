#!/bin/bash

# Add MobileEntitlements property to Auth.swift
# This script is idempotent and cross-platform compatible

set -e  # Exit on any error

# Detect sed type for cross-platform compatibility
if sed --version >/dev/null 2>&1; then
    # GNU sed
    SED_INPLACE="sed -i"
else
    # BSD sed (macOS)
    SED_INPLACE="sed -i ''"
fi

# Check for Auth.swift in the correct location (generator template)
AUTH_FILE="Auth/Auth.swift"

if [ ! -f "$AUTH_FILE" ]; then
    echo "❌ Auth.swift file not found at $AUTH_FILE"
    echo "   Expected to find the generator template file"
    exit 1
fi

echo "🔍 Checking Auth.swift for MobileEntitlements property..."

# Check if MobileEntitlements property already exists
if grep -q "public lazy var entitlements: MobileEntitlements" "$AUTH_FILE"; then
    echo "✅ MobileEntitlements property already exists in Auth.swift"
    exit 0
fi

# Check if MobileEntitlements class is defined in the file
if ! grep -q "public class MobileEntitlements" "$AUTH_FILE"; then
    echo "❌ MobileEntitlements class not found in Auth.swift"
    echo "   Make sure MobileEntitlements is defined before running this script"
    exit 1
fi

# Check if ClaimsService property exists (our insertion point)
if ! grep -q "public lazy var claims: ClaimsService" "$AUTH_FILE"; then
    echo "❌ ClaimsService property not found in Auth.swift"
    echo "   Cannot determine insertion point for MobileEntitlements property"
    exit 1
fi

echo "📝 Adding MobileEntitlements property to Auth.swift..."

# Add the MobileEntitlements property after the claims property
# Use a more robust approach that works with both GNU and BSD sed
$SED_INPLACE '/public lazy var claims: ClaimsService = ClaimsService(auth: self, logger: logger)/a\
\
    /// Mobile entitlements system for client-side validation\
    public lazy var entitlements: MobileEntitlements = MobileEntitlements(auth: self, logger: logger)\
' "$AUTH_FILE"

# Verify the addition was successful
if grep -q "public lazy var entitlements: MobileEntitlements" "$AUTH_FILE"; then
    echo "✅ MobileEntitlements property successfully added to Auth.swift"
else
    echo "❌ Failed to add MobileEntitlements property to Auth.swift"
    exit 1
fi

echo "🎉 Script completed successfully!"
