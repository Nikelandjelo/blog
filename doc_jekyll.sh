#https://pages.github.com/versions/
export JEKYLL_VERSION=latest #3.9.3

# In case of Gemfile.lock error
#chmod -R a+w .

function jekyll_build() {
  docker run --rm \
    --volume="$PWD:/srv/jekyll:Z" \
    -it jekyll/jekyll:$JEKYLL_VERSION \
    jekyll build
}

function jekyll_serve() {
  docker run --rm \
    --volume="$PWD:/srv/jekyll:Z" \
    --publish [::1]:4000:4000 \
    --dns=8.8.8.8 \
    jekyll/jekyll \
    jekyll serve
}

function jekyll_update() {
  docker run --rm \
    --volume="$PWD:/srv/jekyll:Z" \
    -it jekyll/jekyll:$JEKYLL_VERSION \
    bundle update
}

# Main
if [ "$1" == "build" ]; then
  jekyll_build
elif [ "$1" == "serve" ]; then
  jekyll_serve
elif [ "$1" == "update" ]; then
  jekyll_update
else
  echo "Usage: $0 [build|serve|update]"
fi
