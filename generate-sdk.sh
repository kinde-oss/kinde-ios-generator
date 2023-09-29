#!/bin/bash

# Define paths
sdk_directory="./KindeManagementAPI"
xcode_project="CustomFiles/KindeSDK.xcodeproj"

# Generate the SDK using openapi-generator-cli
npx rimraf "$sdk_directory"
npx @openapitools/openapi-generator-cli generate -i kinde-mgmt-api-specs.yaml -g swift5 -o "$sdk_directory" -c config.yaml --ignore-file-override=./.openapi-generator-ignore

# Copy the Xcode project to the SDK directory
cp -r "$xcode_project" "$sdk_directory"

# Move the docs directory in generated sdk to the source folder
mv "$sdk_directory/docs" "$sdk_directory/sources"
