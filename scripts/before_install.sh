#!/bin/bash

# Accept Android SDK licenses
yes | sdkmanager --licenses

# Install required Android SDK components
sdkmanager "platforms;android-34" "build-tools;34.0.0" "ndk;25.2.9519653" 