# BEGIN_LEGAL
#
# Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
#
# This file and all technical concepts, proprietary knowledge, algorithms and
# intellectual property rights it contains (collectively the "Confidential Information"),
# are the sole propriety information of Cisco and shall remain at Cisco's ownership.
# You shall not disclose the Confidential Information to any third party and you
# shall use it solely in connection with operating and/or maintaining of Cisco's
# products and pursuant to the terms and conditions of the license agreement you
# entered into with Cisco.
#
# THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
# IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
# AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
# THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#
# END_LEGAL

DOCKER_SHA1_FILES := \
	docker/Dockerfile.python \
	docker/Dockerfile.user \
	docker/sonic-jenkins-id_rsa.pub \
	docker/quiltrc-dpkg

USER := $(shell $(UNLOGGED) id -un | tr A-Z a-z)
UID := $(shell $(UNLOGGED) id -u $(USER))
GUID := $(shell $(UNLOGGED) id -g $(USER))
FULLNAME :=  $(shell $(UNLOGGED) getent passwd $(USER) | cut -d ':' -f 5)
HOSTNAME := silicon-one
no_proxy ?= localhost

TAG := $(shell $(UNLOGGED) cat $(DOCKER_SHA1_FILES) | sha1sum)
TAG := $(shell echo $(TAG) | cut -c1-13)
SILICON-ONE_SLAVE := $(shell $(UNLOGGED) docker image inspect $(SILICON-ONE_IMAGE)-$(USER):$(TAG) > /dev/null 2>&1 || echo $(SILICON-ONE_IMAGE)-$(USER))

PYTHON_VER-$(SILICON-ONE_IMAGE) := 3.8.0
PYTHON_VER-silicon_one-slave-stretch := 3.8.0
PYTHON_VER-silicon_one-slave-buster := 3.8.0
PYTHON_VER-silicon_one-slave := 3.8.0
PYTHON_VER := $(PYTHON_VER-$(SILICON-ONE_IMAGE))

PYTHON_RC-$(SILICON-ONE_IMAGE) := a3
PYTHON_RC-silicon_one-slave-stretch := a3
PYTHON_RC-silicon_one-slave-buster := a3
PYTHON_RC-silicon_one-slave := a3
PYTHON_RC := $(PYTHON_RC-$(SILICON-ONE_IMAGE))

PYTHON_BASE_IMAGE-$(SILICON-ONE_IMAGE) := debian:$(DEBIAN_CODENAME)
PYTHON_BASE_IMAGE-silicon_one-slave-$(DEBIAN_CODENAME) := debian:$(DEBIAN_CODENAME)
PYTHON_BASE_IMAGE := $(PYTHON_BASE_IMAGE-$(SILICON-ONE_IMAGE))

# $1 image name
# $2 dependent base image
# $3 Dockerfile
define docker_build
if docker image inspect $(1):$(TAG) > /dev/null 2>&1; then \
	mkdir -p docker/$(1); \
else \
	rm -rf docker/$(1) && \
	mkdir docker/$(1) && \
	ln $(DOCKER_SHA1_FILES) docker/$(1) && \
	sed -e "s/{TAG}/$(TAG)/g" \
	-e "s/{SILICON-ONE_IMAGE}/$(SILICON-ONE_IMAGE)/g" \
	-e "s/{PYTHON_VER}/$(PYTHON_VER)/g" \
	-e "s/{PYTHON_RC}/$(PYTHON_RC)/g" \
	-e "s/{PYTHON_BASE_IMAGE}/$(PYTHON_BASE_IMAGE)/g" \
	docker/$(1)/$(3) > docker/$(1)/Dockerfile && \
	docker build --no-cache \
	--label Tag=$(TAG) \
	-t $(1) \
	--build-arg no_proxy=${no_proxy} \
	--build-arg user=$(USER) \
	--build-arg uid=$(UID) \
	--build-arg guid=$(GUID) \
	--build-arg hostname=$(HOSTNAME) \
	--build-arg 'fullname=$(FULLNAME)' \
	docker/$(1)/. && \
	docker image tag $(1):latest $(1):$(TAG) ; \
fi
endef

docker/$(SILICON-ONE_IMAGE)-python/$(TAG): $(DOCKER_SHA1_FILES)
	@$(call docker_build,$(SILICON-ONE_IMAGE)-python,$(SILICON-ONE_IMAGE)-base:latest,Dockerfile.python)
	@touch $@

docker/$(SILICON-ONE_IMAGE)-$(USER)/$(TAG): docker/$(SILICON-ONE_IMAGE)-python/$(TAG)
docker/$(SILICON-ONE_IMAGE)-$(USER)/$(TAG): $(DOCKER_SHA1_FILES)
	@$(call docker_build,$(SILICON-ONE_IMAGE)-$(USER),$(SILICON-ONE_IMAGE)-python:$(TAG),Dockerfile.user)
	@touch $@

.PHONY: $(SILICON-ONE_IMAGE)-$(USER)
$(SILICON-ONE_IMAGE)-$(USER): docker/$(SILICON-ONE_IMAGE)-$(USER)/$(TAG)
