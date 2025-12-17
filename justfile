# pushes all changes to the main branch
push +COMMIT_MESSAGE:
  git add .
  git commit -m "{{COMMIT_MESSAGE}}"
  git pull origin main
  git push origin main

clear-kc-data:
  rm -rf hack/compose/keycloak/data/*

start-dev:
  docker-compose -f hack/compose/docker-compose.yml up -d

stop-dev:
  docker-compose -f hack/compose/docker-compose.yml down