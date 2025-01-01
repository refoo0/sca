SUBDIRS = awesome-go caddy frp fzf gin go hugo kubernetes ollama syncthing

#SUBDIRS = syncthing

SUBDIR = testAnwendungen/app4

RESULT_DIR = results
RESULT_DIR_PATH = $(RESULT_DIR)/$(SUBDIR)

SCAN_DIR = app
SCAN_APP_PATH = $(SCAN_DIR)/$(SUBDIR)



run::
	./scripts/scan.sh $(RESULT_DIR_PATH) $(SCAN_APP_PATH)

o::	
	./scripts/scanner/osv.sh "" $(SCAN_APP_PATH)

s::	
	./scripts/scanner/snyk.sh "" $(SCAN_APP_PATH)

t::	
	./scripts/scanner/trivy.sh "" $(SCAN_APP_PATH)

r::
	@for subdir in $(SUBDIRS); do \
		echo "Running analysis for $$subdir"; \
		go run ./scan/main.go analysis \
			$(RESULT_DIR)/$$subdir/osv.json \
			$(RESULT_DIR)/$$subdir/trivy.json \
			$(RESULT_DIR)/$$subdir/snyk.json \
			$(RESULT_DIR)/$$subdir; \
	done
generate::
	go run ./scan/main.go generate ./results/scanner/projectsResults output.json  

sbom::
	./scripts/sbom.sh $(SCAN_APP_PATH) 