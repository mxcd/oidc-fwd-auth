clear-kc-data:
  rm -rf hack/compose/keycloak/data/*

start-dev:
  docker-compose -f hack/compose/docker-compose.yml up -d

stop-dev:
  docker-compose -f hack/compose/docker-compose.yml down