### Using Docker (Recommended)

```bash
docker build -f Dockerfile --platform linux/x86_64 -t iris:latest .
docker run --platform=linux/amd64 -it iris:latest
```

Note: Read the instructions for "Native Setup" ahead if you intend to configure Java build tools (JDK, Maven, Gradle) or CodeQL.
