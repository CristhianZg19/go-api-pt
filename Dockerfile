# Usar la imagen base de Go en Alpine Linux
FROM golang:1.22-alpine

# Configurar el directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiar los archivos de módulos y descargar las dependencias
COPY go.mod ./
COPY go.sum ./
RUN go mod download

# Copiar el resto de los archivos de la aplicación
COPY *.go ./

# Construir el ejecutable de la aplicación
RUN go build -o /go-api

# Exponer el puerto en el que la aplicación escuchará
EXPOSE 3000

# Comando para ejecutar la aplicación
CMD ["/go-api"]
