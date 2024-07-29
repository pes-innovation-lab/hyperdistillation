build:
	go build
run:
	sudo ./hyperdistillation
log:
	sudo ./hyperdistillation > log.txt
graph:
	dot -Tsvg -O graph.gv
