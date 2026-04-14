package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	port := "5995"
	dir := "/Users/davidbowman/projects/rustwaf/website/dist"

	fmt.Printf("Serving %s on http://localhost:%s\n", dir, port)
	err := http.ListenAndServe(":"+port, http.FileServer(http.Dir(dir)))
	if err != nil {
		fmt.Println("Error:", err)
		os.Exit(1)
	}
}
