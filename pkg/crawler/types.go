package crawler

type GCSListResponse struct {
	NextPageToken string   `json:"nextPageToken,omitempty"`
	Items         []Item   `json:"items,omitempty"`
	Prefixes      []string `json:"prefixes,omitempty"`
}

type Item struct {
	Name string `json:"name"`
}

type Index struct {
	SHA1 string `json:"1"`
}
