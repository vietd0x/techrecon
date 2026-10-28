.PHONY: build run scan report engines clean

IMAGE := techrecon:latest
INPUT_DIR := $(CURDIR)/data/input
OUTPUT_DIR := $(CURDIR)/data/output

build:
	docker build -t $(IMAGE) .

run:
	docker run --rm --network host \
		-v $(INPUT_DIR):/data/input \
		-v $(OUTPUT_DIR):/data/output \
		$(IMAGE) $(ARGS)

scan:
	@mkdir -p $(INPUT_DIR) $(OUTPUT_DIR)
	docker run --rm --network host \
		-v $(INPUT_DIR):/data/input \
		-v $(OUTPUT_DIR):/data/output \
		$(IMAGE) scan \
		-i /data/input/targets.csv \
		-o /data/output/technology_ver.csv \
		--output-dir /data/output \
		-v

report:
	docker run --rm \
		-v $(OUTPUT_DIR):/data/output \
		$(IMAGE) report -i /data/output/technology_ver.csv --all

engines:
	docker run --rm $(IMAGE) engines

clean:
	rm -rf data/output/*.jsonl data/output/*.txt
