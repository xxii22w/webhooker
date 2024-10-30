package main

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

// 客户端
func main() {
	router := http.NewServeMux()

	router.HandleFunc("POST /payments/webhook", handlePaymentWebhook)

	http.ListenAndServe(":3000", router)
}

type WebhookRequest struct {
	Amount  int    `json:"amount"`
	Message string `json:"message`
}

// 接受post发送的数据
func handlePaymentWebhook(w http.ResponseWriter, r *http.Request) {
	b, err := io.ReadAll(r.Body)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(string(b))
}
