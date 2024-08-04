package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/golang-jwt/jwt/v5"
	"gonum.org/v1/gonum/mat"
)

// MatrixRequest representa la estructura de la solicitud que contiene la matriz
type MatrixRequest struct {
	Matrix [][]float64 `json:"matrix"`
}

// StatisticsResponse representa la estructura de la respuesta que contiene estadísticas de la matriz
type StatisticsResponse struct {
	Max        float64 `json:"max"`
	Min        float64 `json:"min"`
	Sum        float64 `json:"sum"`
	Avg        float64 `json:"avg"`
	IsDiagonal bool    `json:"isDiagonal"`
}

// QRResponse representa la estructura de la respuesta que contiene las matrices Q y R
type QRResponse struct {
	QMatrix [][]float64 `json:"Q"`
	RMatrix [][]float64 `json:"R"`
}

// Clave secreta para firmar el JWT
var JWTSecret = []byte("clave_secreta_matrix")

// rotateMatrix toma una matriz y devuelve las matrices QR
func rotateMatrix(matrix [][]float64) (mat.QR, *mat.Dense) {
	a := mat.NewDense(len(matrix), len(matrix[0]), nil)
	for i, row := range matrix {
		for j, val := range row {
			a.Set(i, j, val)
		}
	}
	var qr mat.QR
	qr.Factorize(a)

	var q mat.Dense
	qr.QTo(&q)

	return qr, &q
}

// Middleware para verificar el token JWT
func verifyToken(c *fiber.Ctx) error {
	tokenString := c.Get("Authorization")
	if tokenString == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "No token provided"})
	}

	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return JWTSecret, nil
	})

	if err != nil || !token.Valid {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid token"})
	}

	return c.Next()
}

// Ruta para autenticar y generar un token JWT
func loginHandler(c *fiber.Ctx) error {
	var req map[string]string
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	username, password := req["username"], req["password"]
	// Aquí deberías verificar las credenciales del usuario
	if username == "admin" && password == "password" {
		token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
			"id":  username,
			"exp": time.Now().Add(time.Hour * 1).Unix(),
		})
		tokenString, err := token.SignedString(JWTSecret)
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		return c.JSON(fiber.Map{"token": tokenString})
	}

	return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
}

// rotateStatisticsHandler maneja la solicitud para rotar la matriz y calcular estadísticas
func rotateStatisticsHandler(c *fiber.Ctx) error {
	var req MatrixRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	// Extraer el token JWT de la cabecera Authorization
	tokenString := c.Get("Authorization")
	if tokenString == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "No token provided"})
	}

	// Realizar la solicitud para obtener estadísticas
	_, q := rotateMatrix(req.Matrix)

	// Convertir la matriz Q a un slice
	qMatrix := matrixToSlice(q)

	// Enviar la matriz a la API de Node.js con el token JWT
	stats, err := getStatistics(qMatrix, tokenString) // Enviar el token a la función
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.Status(http.StatusOK).JSON(stats)
}

// getQRHandler maneja la solicitud para obtener las matrices QR
func getQRHandler(c *fiber.Ctx) error {
	var req MatrixRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	qr, q := rotateMatrix(req.Matrix)

	// Create Dense matrix for R
	var r mat.Dense
	qr.RTo(&r)

	// Convert matrices to slice
	qMatrixSlice := matrixToSlice(q)
	rMatrixSlice := matrixToSlice(&r)

	// Create a response object with both Q matrix and R matrix
	response := QRResponse{
		QMatrix: qMatrixSlice,
		RMatrix: rMatrixSlice,
	}

	return c.Status(http.StatusOK).JSON(response)
}

// getStatistics envía la matriz a la API de Node.js y obtiene las estadísticas
func getStatistics(matrix [][]float64, tokenString string) (*StatisticsResponse, error) {
	jsonData, err := json.Marshal(fiber.Map{"matrix": matrix})
	if err != nil {
		return nil, err
	}

	// Crear una nueva solicitud con el token JWT
	req, err := http.NewRequest("POST", "https://node-api-pt.onrender.com/calculate-statistics", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, err
	}

	// Agregar encabezados a la solicitud
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", tokenString) // token para enviar a la API de node

	// Crear un cliente HTTP y hacer la solicitud
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var stats StatisticsResponse
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		return nil, err
	}

	return &stats, nil
}

// matrixToSlice convierte una matriz densa a un slice de slices
func matrixToSlice(m *mat.Dense) [][]float64 {
	rows, cols := m.Dims()
	data := make([][]float64, rows)
	for i := range data {
		data[i] = make([]float64, cols)
		for j := 0; j < cols; j++ {
			data[i][j] = m.At(i, j)
		}
	}
	return data
}

func main() {
	app := fiber.New()

	app.Use(cors.New(cors.Config{
		AllowOrigins: "*", // Permitir cualquier origen
		AllowHeaders: "Origin, Content-Type, Accept, Authorization",
		AllowMethods: "GET, POST, PUT, DELETE, OPTIONS", // Permitir los métodos que necesites
	}))

	app.Post("/login", loginHandler)
	app.Post("/rotate-statistics", verifyToken, rotateStatisticsHandler)
	app.Post("/get-qr", verifyToken, getQRHandler)

	log.Fatal(app.Listen(":3000"))
}
