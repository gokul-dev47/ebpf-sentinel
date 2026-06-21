# Contributing to eBPF Sentinel

Thank you for your interest in contributing to eBPF Sentinel!

## How to Contribute

### Reporting Bugs
1. Check existing [Issues](https://github.com/gokul-dev47/ebpf-sentinel/issues)
2. Open a new issue with:
   - Linux kernel version (`uname -r`)
   - Distribution name
   - Steps to reproduce
   - Expected vs actual behavior

### Suggesting Features
Open an issue with the `enhancement` label and describe:
- What problem it solves
- How it should work
- Any relevant MITRE ATT&CK techniques

### Submitting Code

```bash
# Fork the repo
git clone https://github.com/YOUR-USERNAME/ebpf-sentinel
cd ebpf-sentinel

# Create a feature branch
git checkout -b feature/your-feature-name

# Make changes and test
go test ./...
sudo ./bin/sentinel scan --verbose

# Commit with clear message
git commit -m "feat: describe what you added"

# Push and open a Pull Request
git push origin feature/your-feature-name
```

## Code Standards

- All exported functions must have doc comments
- Error handling: never ignore errors, wrap with context
- Follow existing patterns in `pkg/detector/`
- Add tests for new detection modules

## Detection Module Template

```go
type MyDetector struct {
    log    *logrus.Logger
    loader *loader.Loader
}

func NewMyDetector(log *logrus.Logger, ldr *loader.Loader) *MyDetector {
    return &MyDetector{log: log, loader: ldr}
}

func (d *MyDetector) Name() string { return "MyDetector" }

func (d *MyDetector) Run(ctx context.Context, results *ScanResults) error {
    // Detection logic here
    return nil
}

func (d *MyDetector) Remediate(ctx context.Context, findings []*Finding, dryRun bool) ([]string, error) {
    return nil, nil
}
```

## License

By contributing, you agree that your contributions will be licensed under GPLv2.
