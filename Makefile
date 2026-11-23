.PHONY: build run run-local test test-e2e release engine-checksums app universal dist sign notarize dmg

VERSION ?= $(shell sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -1)
API ?= https://api.thelemail.com
WEB ?= https://app.thelemail.com
AUTH ?= https://auth.thelemail.com
LOCAL_API ?= http://localhost:8180
LOCAL_WEB ?= http://localhost:5173
LOCAL_AUTH ?= http://localhost:5177
CONFIG := github.com/thelemail/migrator/engine/internal/config
LDFLAGS = -s -w -buildid= -X $(CONFIG).Version=$(VERSION) -X $(CONFIG).API=$(API) -X $(CONFIG).Web=$(WEB) -X $(CONFIG).Auth=$(AUTH)
EXE := $(if $(filter Windows_NT,$(OS)),.exe,)
APP := dist/Thelemail Migrator.app
DMG = dist/Thelemail-Migrator-$(VERSION)-macos.dmg
IDENTITY ?=
NOTARY_PROFILE ?= thelemail-notary

build:
	cargo build --locked
	cd engine && go build -trimpath -ldflags "$(LDFLAGS)" -o ../target/debug/migrator-engine$(EXE) .

run: build
	./target/debug/thelemail-migrator

run-local:
	cargo build --locked
	cd engine && go build -trimpath -tags localstack -ldflags "$(LDFLAGS) -X $(CONFIG).API=$(LOCAL_API) -X $(CONFIG).Web=$(LOCAL_WEB) -X $(CONFIG).Auth=$(LOCAL_AUTH)" -o ../target/debug/migrator-engine$(EXE) .
	./target/debug/thelemail-migrator

test:
	cd engine && go vet ./... && go test -race ./...
	cargo test --locked

test-e2e:
	cd engine && go test -tags e2e,localstack -count=1 -run "^Test" .

release:
	VERSION=$(VERSION) API=$(API) WEB=$(WEB) AUTH=$(AUTH) ./scripts/build-release.sh

engine-checksums:
	VERSION=$(VERSION) API=$(API) WEB=$(WEB) AUTH=$(AUTH) ./scripts/engine-checksums.sh

universal:
	cargo build --release --locked --target aarch64-apple-darwin
	cargo build --release --locked --target x86_64-apple-darwin
	mkdir -p target/universal
	lipo -create -output target/universal/thelemail-migrator target/aarch64-apple-darwin/release/thelemail-migrator target/x86_64-apple-darwin/release/thelemail-migrator
	VERSION=$(VERSION) API=$(API) WEB=$(WEB) AUTH=$(AUTH) ./scripts/build-engine.sh darwin arm64 target/universal/migrator-engine-arm64
	VERSION=$(VERSION) API=$(API) WEB=$(WEB) AUTH=$(AUTH) ./scripts/build-engine.sh darwin amd64 target/universal/migrator-engine-amd64
	lipo -create -output target/universal/migrator-engine target/universal/migrator-engine-arm64 target/universal/migrator-engine-amd64

app: universal
	rm -rf "$(APP)"
	mkdir -p "$(APP)/Contents/MacOS" "$(APP)/Contents/Resources"
	cp assets/AppIcon.icns "$(APP)/Contents/Resources/"
	cp target/universal/thelemail-migrator target/universal/migrator-engine "$(APP)/Contents/MacOS/"
	sed 's/@VERSION@/$(VERSION)/g' Info.plist > "$(APP)/Contents/Info.plist"

sign: app
	test -n "$(IDENTITY)"
	codesign --force --options runtime --timestamp --sign "$(IDENTITY)" "$(APP)/Contents/MacOS/migrator-engine"
	codesign --force --options runtime --timestamp --sign "$(IDENTITY)" "$(APP)/Contents/MacOS/thelemail-migrator"
	codesign --force --options runtime --timestamp --sign "$(IDENTITY)" "$(APP)"
	codesign --verify --deep --strict "$(APP)"

notarize: sign
	ditto -c -k --keepParent "$(APP)" dist/notarize.zip
	xcrun notarytool submit dist/notarize.zip --keychain-profile "$(NOTARY_PROFILE)" --wait
	rm dist/notarize.zip
	xcrun stapler staple "$(APP)"
	$(MAKE) dmg
	codesign --force --timestamp --sign "$(IDENTITY)" "$(DMG)"
	xcrun notarytool submit "$(DMG)" --keychain-profile "$(NOTARY_PROFILE)" --wait
	xcrun stapler staple "$(DMG)"

dmg:
	rm -rf dist/dmg "$(DMG)"
	mkdir -p dist/dmg
	ditto "$(APP)" "dist/dmg/Thelemail Migrator.app"
	ln -s /Applications dist/dmg/Applications
	hdiutil create -volname "Thelemail Migrator" -srcfolder dist/dmg -fs HFS+ -format UDZO -ov "$(DMG)"
	rm -rf dist/dmg
