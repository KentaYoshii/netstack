all:
	go build -o vhost ./cmd/vhost/main.go
	go build -o vrouter ./cmd/vrouter/main.go
clean:
	rm -f ./vhost
	rm -f ./vrouter