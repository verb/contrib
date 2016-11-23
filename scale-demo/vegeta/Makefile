all: push

# See pod.yaml for the version currently running-- bump this ahead before rebuilding!
IMAGE = gcr.io/google_containers/loader
TAG = 0.7

loader: loader.go
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 godep go build -a -installsuffix cgo -ldflags '-w' -o loader

container: loader
	docker build -t $(IMAGE):$(TAG) .

push: container
	gcloud docker push $(IMAGE):$(TAG)

clean:
	rm -f loader
