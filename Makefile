#SUBDIRS = awesome-go caddy frp fzf gin go hugo kubernetes ollama syncthing

SUBDIRS = testfall-1/app1 testfall-1/app2 testfall-2/app1 testfall-2/app2 testfall-3/app1 testfall-3/app2 testfall-4/app1 testfall-4/app2 testfall-5/app1 testfall-5/app2 testfall-6/app1 testfall-6/app2 testfall-7/app1 testfall-7/app2 testfall-8/app1 testfall-9/app1 testfall-10/app1 testfall-11/app1 testfall-12/app3 testfall-13/app3 testfall-14/app3 testfall-15/app3 testfall-16/app3 testfall-17/app3 testfall-18/app3

#SUBDIRS = syncthing

#SUBDIR = testAnwendungen/app4

#RESULT_DIR = results/projects
RESULT_DIR = results/testAnwendungen
RESULT_DIR_PATH = $(RESULT_DIR)/$(SUBDIR)

#SCAN_DIR = app/projects
SCAN_DIR = app/testAnwendungen
SCAN_APP_PATH = $(SCAN_DIR)/$(SUBDIR)



run::
	@for subdir in $(SUBDIRS); do \
		echo "Running scan for $$subdir"; \
		./scripts/scan.sh $(RESULT_DIR)/$$subdir $(SCAN_DIR)/$$subdir; \
	done

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