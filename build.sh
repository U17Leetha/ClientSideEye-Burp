#!/bin/bash
set -euo pipefail

./gradlew clean jar

# The Gradle build now refreshes ./ClientSideEye-Burp.jar automatically.
