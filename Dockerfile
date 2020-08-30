FROM node:alpine as vue-build
COPY vue /app
WORKDIR /app
RUN yarn install
RUN yarn build

FROM tiangolo/uvicorn-gunicorn-fastapi:python3.8-alpine3.10
COPY ./api /app
COPY --from=vue-build /app/dist /app/vue
WORKDIR /app
RUN apk add build-base
RUN apk add libffi-dev python-dev openssl-dev
RUN /usr/local/bin/python -m pip install --upgrade pip
RUN pip install -r ./requirements.txt
ENV API_ENV DOCKER
CMD ["uvicorn", "healthid:app", "--host", "0.0.0.0", "--port", "8000"]
EXPOSE 8000