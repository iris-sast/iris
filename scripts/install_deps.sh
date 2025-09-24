#!/usr/bin/env bash
set -e

# ---- Configurable installation directory ----
INSTALL_DIR="/iris/test"
GRADLE_DIR="$INSTALL_DIR/gradle"
MAVEN_DIR="$INSTALL_DIR/maven"
JVM_DIR="$INSTALL_DIR/jvm"

# ADOPTIUM PARAMETERS FOR JDKS; Change according to you system
OS="linux"
ARCH="x64"
IMAGE_TYPE="jdk"

# ---- JDK URLs ----
declare -A JDK_URLS=(
  [8]="https://api.adoptium.net/v3/binary/latest/8/ga/${OS}/${ARCH}/${IMAGE_TYPE}/hotspot/normal/eclipse"
  [11]="https://api.adoptium.net/v3/binary/latest/11/ga/${OS}/${ARCH}/${IMAGE_TYPE}/hotspot/normal/eclipse"
  [17]="https://api.adoptium.net/v3/binary/latest/17/ga/${OS}/${ARCH}/${IMAGE_TYPE}/hotspot/normal/eclipse"
)

# ---- Maven URLs ----
declare -A MAVEN_URLS=(
  [3.2.1]="https://archive.apache.org/dist/maven/maven-3/3.2.1/binaries/apache-maven-3.2.1-bin.tar.gz"
  [3.5.0]="https://archive.apache.org/dist/maven/maven-3/3.5.0/binaries/apache-maven-3.5.0-bin.tar.gz"
  [3.9.8]="https://archive.apache.org/dist/maven/maven-3/3.9.8/binaries/apache-maven-3.9.8-bin.tar.gz"
)

# ---- Gradle URLs ----
declare -A GRADLE_URLS=(
  [6.8.2]="https://services.gradle.org/distributions/gradle-6.8.2-bin.zip"
  [7.6.4]="https://services.gradle.org/distributions/gradle-7.6.4-bin.zip"
  [8.9]="https://services.gradle.org/distributions/gradle-8.9-bin.zip"
)

# ---- Functions ----
install_jdk() {
  local version=$1
  local url=${JDK_URLS[$version]}

  if [[ -z "$url" ]]; then
    echo "❌ JDK version $version is not supported."
    return 1
  fi

  echo "🔽 Downloading OpenJDK $version..."
  wget -q "$url" -O /tmp/openjdk-${version}.tar.gz
  
  echo "📦 Extracting to $JVM_DIR..."
  sudo mkdir -p "$JVM_DIR"
  sudo tar -xzf /tmp/openjdk-${version}.tar.gz -C "$JVM_DIR"
 

  # Register with update-alternatives
  local extracted_folder=$(tar -tzf /tmp/openjdk-${version}.tar.gz | head -1 | cut -f1 -d"/")
  local jdk_dir="$JVM_DIR/$extracted_folder"
  if [[ -x "$jdk_dir/bin/java" ]]; then
    echo "⚙️ Registering OpenJDK $version with update-alternatives..."
    #sudo update-alternatives --install /usr/bin/java java "$jdk_dir/bin/java" $version
  fi

  sudo rm /tmp/openjdk-${version}.tar.gz
  echo "✅ Installed OpenJDK $version."
}

install_maven() {
  local version=$1
  local url=${MAVEN_URLS[$version]}

  if [[ -z "$url" ]]; then
    echo "❌ Maven version $version is not supported."
    return 1
  fi

  echo "🔽 Downloading Maven $version..."
  wget -q "$url" -O /tmp/maven-${version}.tar.gz

  echo "📦 Extracting to $MAVEN_DIR..."
  sudo mkdir -p "$MAVEN_DIR"
  sudo tar -xzf /tmp/maven-${version}.tar.gz -C "$MAVEN_DIR"
  sudo rm /tmp/maven-${version}.tar.gz

  echo "✅ Installed Maven $version at $MAVEN_DIR/apache-maven-${version}"
}

install_gradle() {
  local version=$1
  local url=${GRADLE_URLS[$version]}

  if [[ -z "$url" ]]; then
    echo "❌ Gradle version $version is not supported."
    return 1
  fi

  echo "🔽 Downloading Gradle $version..."
  wget -q "$url" -O /tmp/gradle-${version}-bin.zip

  echo "📦 Extracting to $GRADLE_DIR..."
  sudo mkdir -p "$GRADLE_DIR"
  sudo unzip -q /tmp/gradle-${version}-bin.zip -d "$GRADLE_DIR"
  sudo rm /tmp/gradle-${version}-bin.zip

  echo "✅ Installed Gradle $version at $GRADLE_DIR/gradle-${version}"
}

install_docker() {
  echo "🐳 Installing Docker (docker.io)..."
  sudo apt-get update -y
  sudo apt-get install -y docker.io
  if command -v docker >/dev/null 2>&1; then
    echo "✅ Docker installed: $(docker --version)"
  else
    echo "❌ Docker installation failed"
    return 1
  fi
}

# ---- Usage ----
usage() {
  cat <<EOF
Usage:
  $0 jdk [8|11|17]...    (Install one or more JDKs)
  $0 maven [3.2.1|3.5.0|3.9.8]...
  $0 gradle [6.8.2|7.6.4|8.9]...
  $0 docker              (Install Docker CLI/Engine)

Examples:
  $0 jdk 8 11 17
  $0 maven 3.9.8
  $0 gradle 7.6.4 8.9

EOF
  exit 1
}

# ---- Main logic ----
if [[ $# -lt 2 ]]; then
  usage
fi

tool=$1
shift

case "$tool" in
  jdk)
    for v in "$@"; do
      install_jdk "$v"
    done
    ;;
  maven)
    for v in "$@"; do
      install_maven "$v"
    done
    ;;
  gradle)
    for v in "$@"; do
      install_gradle "$v"
    done
    ;;
  
  docker)
    install_docker
    ;;
  *)
    usage
    ;;
esac

echo "🎉 All requested tools have been installed!"
