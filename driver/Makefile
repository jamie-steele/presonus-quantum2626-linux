# Out-of-tree ALSA PCI driver for PreSonus Quantum Thunderbolt Family
# Build: make -C /lib/modules/$(uname -r)/build M=$(PWD) modules
# Load:  sudo insmod snd-quantum.ko  (or modprobe after install)

# --- Configuration Variables (Single Source of Truth) ---

# Module names
MODULE_NAME_NEW := snd-quantum
MODULE_NAME_LEGACY := snd-quantum2626

# Paths
KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
MOD_BASE_DIR ?= /lib/modules/$(shell uname -r)

# Handle DESTDIR for packaging/installation to alternate roots
ifeq ($(DESTDIR),)
    FULL_MOD_BASE_DIR := $(MOD_BASE_DIR)
else
    FULL_MOD_BASE_DIR := $(DESTDIR)$(MOD_BASE_DIR)
endif

UCM2_DIR ?= /usr/share/alsa/ucm2

# UCM Model Names.
# NOTE: 'Quantum' is the base model containing Common.conf.
# Others inherit from it and only contain HiFi.conf.
UCM_MODELS := Quantum Quantum2 Quantum2626 Quantum4848

# WirePlumber versions to support
WP_VERSIONS := 4 5

WP_SOURCE_DIR := ../alsa/wireplumber
WP4_FILE := 51-quantum.lua
WP5_FILE := 51-quantum.conf

WP4_MAIN_LUA_DIR ?= /usr/share/wireplumber/main.lua.d
WP5_MAIN_CONF_DIR ?= /usr/share/wireplumber/wireplumber.conf.d

# --- Helper Functions ---

# Find a module file by name stem (handles .ko, .ko.gz, .ko.xz, .ko.zst)
define find_module
$(shell find $(FULL_MOD_BASE_DIR) -name "$(1).ko*" -type f 2>/dev/null | head -n 1)
endef

# Generic install for a single file
define install_file
	install -D -m 0644 $(1) $(2)
endef

# Generic remove for a single file
define remove_file
	rm -f $(1)
endef

# Helper to remove a module by name stem (keeps target body short)
define remove_module_action
	$(eval MOD_PATH := $(call find_module,$(1)))
	@if [ -n "$(MOD_PATH)" ]; then \
		echo "Found module: $(MOD_PATH). Removing..."; \
		rm -f "$(MOD_PATH)"; \
	else \
		echo "Module $(1) not found. Nothing to remove."; \
	fi
endef

# --- Build Targets ---

obj-m := $(MODULE_NAME_NEW).o

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean

# --- Module Installation Targets ---

install-module: all
	@echo "Installing $(MODULE_NAME_NEW)..."
	$(MAKE) -C $(KDIR) M=$(PWD) modules_install

	@echo "Checking for legacy module $(MODULE_NAME_LEGACY)..."
	$(eval LEGACY_PATH := $(call find_module,$(MODULE_NAME_LEGACY)))
	@if [ -n "$(LEGACY_PATH)" ]; then \
		echo "Found legacy module: $(LEGACY_PATH). Removing..."; \
		rm -f "$(LEGACY_PATH)"; \
	else \
		echo "No legacy module found. Skipping removal."; \
	fi

	depmod -a
	@echo "Module installation complete."

uninstall-module:
	@echo "Uninstalling $(MODULE_NAME_NEW)..."
	$(call remove_module_action,$(MODULE_NAME_NEW))
	depmod -a
	@echo "Module uninstallation complete."

# --- UCM Installation Targets ---

# Dynamic rule generation for UCM models
define UCM_INSTALL_RULES
install-ucm-$(1):
	$(call install_file,../alsa/ucm2/$(1)/HiFi.conf,$(DESTDIR)$(UCM2_DIR)/$(1)/HiFi.conf)
ifeq ($(1),Quantum)
	$(call install_file,../alsa/ucm2/$(1)/Common.conf,$(DESTDIR)$(UCM2_DIR)/$(1)/Common.conf)
endif

uninstall-ucm-$(1):
	$(call remove_file,$(DESTDIR)$(UCM2_DIR)/$(1)/HiFi.conf)
ifeq ($(1),Quantum)
	$(call remove_file,$(DESTDIR)$(UCM2_DIR)/$(1)/Common.conf)
endif
	# Attempt to remove the model directory if it is now empty.
	# This applies to ALL models, not just Quantum.
	-rmdir $(DESTDIR)$(UCM2_DIR)/$(1) 2>/dev/null || true
endef

# Generate rules for each model in $(UCM_MODELS)
$(foreach model,$(UCM_MODELS),$(eval $(call UCM_INSTALL_RULES,$(model))))

# Aggregate targets for UCM
install-ucm: $(foreach model,$(UCM_MODELS),install-ucm-$(model))
	$(call install_file,../alsa/ucm2/conf.d/snd-quantum/snd-quantum.conf,$(DESTDIR)$(UCM2_DIR)/conf.d/snd-quantum/snd-quantum.conf)
	@echo "UCM2 installation complete for models: $(UCM_MODELS)"

uninstall-ucm: $(foreach model,$(UCM_MODELS),uninstall-ucm-$(model))
	$(call remove_file,$(DESTDIR)$(UCM2_DIR)/conf.d/snd-quantum/snd-quantum.conf)
	-rmdir $(DESTDIR)$(UCM2_DIR)/conf.d/snd-quantum 2>/dev/null || true
	@echo "UCM2 uninstallation complete."

# --- WirePlumber Version Detection ---
WP_VERSION_STRING := $(shell wireplumber --version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)

WP_DETECTED_VERSION := $(shell echo "$(WP_VERSION_STRING)" | awk -F. '{ \
    if ($$1 == 0 && $$2 == 4) print 4; \
    else if ($$1 >= 0 && $$2 >= 5) print 5; \
    else print 4 \
}')

# Allow override: make install WP_FORCE_VERSION=5
ifdef WP_FORCE_VERSION
    WP_DETECTED_VERSION := $(WP_FORCE_VERSION)
endif

ifeq ($(WP_DETECTED_VERSION),4)
    WP_INSTALL_TARGET := install-wp4
    WP_UNINSTALL_TARGET := uninstall-wp4
    WP_MSG := "Detected WirePlumber v0.4.x (or fallback). Installing LUA script."
else
    WP_INSTALL_TARGET := install-wp5
    WP_UNINSTALL_TARGET := uninstall-wp5
    WP_MSG := "Detected WirePlumber v0.5.x+. Installing CONF file."
endif

# --- WirePlumber Installation Targets ---

WP4_SRC := $(WP_SOURCE_DIR)/$(WP4_FILE)
WP4_DEST := $(WP4_MAIN_LUA_DIR)/$(WP4_FILE)

WP5_SRC := $(WP_SOURCE_DIR)/$(WP5_FILE)
WP5_DEST := $(WP5_MAIN_CONF_DIR)/$(WP5_FILE)

# Generic Install/Remove Helpers
define wp_install
	$(call install_file,$(1),$(2))
endef

define wp_remove
	$(call remove_file,$(1))
endef

# Migration Helper: Removes the "other" version before installing
# Usage: $(call migrate_cleanup,4) -> removes v5 files
# Usage: $(call migrate_cleanup,5) -> removes v4 files
define migrate_cleanup
	@if [ "$(1)" = "4" ]; then \
		echo "Cleaning up legacy v0.5+ files..."; \
		rm -f "$(DESTDIR)$(WP5_DEST)"; \
	elif [ "$(1)" = "5" ]; then \
		echo "Cleaning up legacy v0.4 files..."; \
		rm -f "$(DESTDIR)$(WP4_DEST)"; \
	fi
endef

# Specific targets
install-wp4:
	@echo "Installing WirePlumber 0.4 configuration ($(WP4_FILE))..."
	$(call migrate_cleanup,4)
	$(call install_file,$(WP4_SRC),$(DESTDIR)$(WP4_DEST))

uninstall-wp4:
	@echo "Uninstalling WirePlumber 0.4 configuration ($(WP4_FILE))..."
	$(call remove_file,$(DESTDIR)$(WP4_DEST))

install-wp5:
	@echo "Installing WirePlumber 0.5+ configuration ($(WP5_FILE))..."
	$(call migrate_cleanup,5)
	$(call install_file,$(WP5_SRC),$(DESTDIR)$(WP5_DEST))

uninstall-wp5:
	@echo "Uninstalling WirePlumber 0.5+ configuration ($(WP5_FILE))..."
	$(call remove_file,$(DESTDIR)$(WP5_DEST))

# Dynamic aggregate targets based on detection
install-wp:
	@echo $(WP_MSG)
	$(MAKE) $(WP_INSTALL_TARGET)

uninstall-wp:
	@echo "Removing WirePlumber configuration (auto-detected version)..."
	# Attempt to remove both to be safe in case version changed since install
	$(MAKE) uninstall-wp4
	$(MAKE) uninstall-wp5
	@echo "WirePlumber uninstallation complete."

# --- Global Aggregates ---

install-audio: install-ucm install-wp
uninstall-audio: uninstall-ucm uninstall-wp

install: install-module install-audio
uninstall: uninstall-module uninstall-audio

# Dummy test target to satisfy linters
test:
	@echo "No automated tests defined yet. Manual testing required."

# --- PHONY Declarations ---
# Explicitly listing aggregate targets to satisfy checkmake
.PHONY: all clean test
.PHONY: install uninstall
.PHONY: install-module uninstall-module
.PHONY: install-ucm uninstall-ucm
.PHONY: install-wp uninstall-wp
.PHONY: install-audio uninstall-audio
# Dynamic model targets
.PHONY: $(foreach model,$(UCM_MODELS),install-ucm-$(model) uninstall-ucm-$(model))
# Dynamic WP targets
.PHONY: $(foreach ver,$(WP_VERSIONS),install-wp$(ver) uninstall-wp$(ver))
