package tus

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/suite"
	"github.com/tus/tusd/pkg/filestore"
	"github.com/tus/tusd/pkg/handler"
)

type MockStore struct {
	m map[string]string
}

func NewMockStore() Store {
	return &MockStore{
		make(map[string]string),
	}
}

func (s *MockStore) Get(fingerprint string) (string, bool) {
	url, ok := s.m[fingerprint]
	return url, ok
}

func (s *MockStore) Set(fingerprint, url string) {
	s.m[fingerprint] = url
}

func (s *MockStore) Delete(fingerprint string) {
	delete(s.m, fingerprint)
}

func (s *MockStore) Close() {
	for k := range s.m {
		delete(s.m, k)
	}
}

type UploadTestSuite struct {
	suite.Suite

	ts    *httptest.Server
	store filestore.FileStore
	url   string
}

func (s *UploadTestSuite) SetupSuite() {
	store := filestore.FileStore{
		Path: os.TempDir(),
	}

	composer := handler.NewStoreComposer()

	store.UseIn(composer)

	handler, err := handler.NewHandler(handler.Config{
		BasePath:                "/uploads/",
		StoreComposer:           composer,
		MaxSize:                 0,
		NotifyCompleteUploads:   false,
		NotifyTerminatedUploads: false,
		RespectForwardedHeaders: true,
	})

	if err != nil {
		panic(err)
	}

	s.store = store
	s.ts = httptest.NewServer(http.StripPrefix("/uploads/", handler))
	s.url = fmt.Sprintf("%s/uploads/", s.ts.URL)
}

func (s *UploadTestSuite) TearDownSuite() {
	s.ts.Close()
}

func (s *UploadTestSuite) TestSmallUploadFromFile() {
	file := fmt.Sprintf("%s/%d", os.TempDir(), time.Now().Unix())

	f, err := os.Create(file)
	s.Nil(err)

	defer f.Close()

	err = f.Truncate(1048576) // 1 MB
	s.Nil(err)

	client, err := NewClient(s.url, nil)
	s.Nil(err)

	upload, err := NewUploadFromFile(f)
	s.Nil(err)

	uploader, err := client.CreateUpload(upload)
	s.Nil(err)
	s.NotNil(uploader)

	err = uploader.Upload()
	s.Nil(err)

	getUpload, err := s.store.GetUpload(nil, uploadIdFromUrl(uploader.url))
	s.Nil(err)

	fi, err := getUpload.GetInfo(nil)
	s.Nil(err)

	s.EqualValues(1048576, fi.Size)
}

func (s *UploadTestSuite) TestLargeUpload() {
	file := fmt.Sprintf("%s/%d", os.TempDir(), time.Now().Unix())

	f, err := os.Create(file)
	s.Nil(err)

	defer f.Close()

	err = f.Truncate(1048576 * 150) // 150 MB
	s.Nil(err)

	client, err := NewClient(s.url, nil)
	s.Nil(err)

	upload, err := NewUploadFromFile(f)
	s.Nil(err)

	uploader, err := client.CreateUpload(upload)
	s.Nil(err)
	s.NotNil(uploader)

	err = uploader.Upload()
	s.Nil(err)

	getUpload, err := s.store.GetUpload(nil, uploadIdFromUrl(uploader.url))
	s.Nil(err)

	fi, err := getUpload.GetInfo(nil)
	s.Nil(err)

	s.EqualValues(1048576*150, fi.Size)
}

func (s *UploadTestSuite) TestUploadFromBytes() {
	client, err := NewClient(s.url, nil)
	s.Nil(err)

	upload := NewUploadFromBytes([]byte("1234567890"))
	s.Nil(err)

	uploader, err := client.CreateUpload(upload)
	s.Nil(err)
	s.NotNil(uploader)

	err = uploader.Upload()
	s.Nil(err)

	getUpload, err := s.store.GetUpload(nil, uploadIdFromUrl(uploader.url))
	s.Nil(err)

	fi, err := getUpload.GetInfo(nil)
	s.Nil(err)

	s.EqualValues(10, fi.Size)
}

func (s *UploadTestSuite) TestOverridePatchMethod() {
	client, err := NewClient(s.url, nil)
	s.Nil(err)

	client.Config.OverridePatchMethod = true

	upload := NewUploadFromBytes([]byte("1234567890"))
	s.Nil(err)

	uploader, err := client.CreateUpload(upload)
	s.Nil(err)
	s.NotNil(uploader)

	err = uploader.Upload()
	s.Nil(err)

	getUpload, err := s.store.GetUpload(nil, uploadIdFromUrl(uploader.url))
	s.Nil(err)

	fi, err := getUpload.GetInfo(nil)
	s.Nil(err)

	s.EqualValues(10, fi.Size)
}

func (s *UploadTestSuite) TestSha1ChecksumChunk() {
	client, err := NewClient(s.url, nil)
	s.Nil(err)

	client.Config.ChecksumAlgorithm = SHA1

	req, _ := http.NewRequest("POST", "https://example.com", nil)
	s.Nil(err)
	err = client.checksumChunk([]byte("hello world"), req)
	s.Nil(err)

	s.EqualValues("sha1 Kq5sNclPz7QV2+lfQIuc6R7oRu0=", req.Header.Get("Upload-Checksum"))
}

func (s *UploadTestSuite) TestSha1HexChecksumChunk() {
	client, err := NewClient(s.url, nil)
	s.Nil(err)

	client.Config.ChecksumAlgorithm = SHA1_HEX

	req, _ := http.NewRequest("POST", "https://example.com", nil)
	s.Nil(err)
	err = client.checksumChunk([]byte("hello world"), req)
	s.Nil(err)
	s.EqualValues("sha1 MmFhZTZjMzVjOTRmY2ZiNDE1ZGJlOTVmNDA4YjljZTkxZWU4NDZlZA==", req.Header.Get("Upload-Checksum"))
}

func (s *UploadTestSuite) TestSha256ChecksumChunk() {
	client, err := NewClient(s.url, nil)
	s.Nil(err)

	client.Config.ChecksumAlgorithm = SHA256

	req, _ := http.NewRequest("POST", "https://example.com", nil)
	s.Nil(err)
	err = client.checksumChunk([]byte("hello world"), req)
	s.Nil(err)

	s.EqualValues("sha256 uU0nuZNNPgilLlLX2n2r+sSE7+N6U4DukIj3rOLvzek=", req.Header.Get("Upload-Checksum"))
}

func (s *UploadTestSuite) TestSha256HexChecksumChunk() {
	client, err := NewClient(s.url, nil)
	s.Nil(err)

	client.Config.ChecksumAlgorithm = SHA256_HEX

	req, _ := http.NewRequest("POST", "https://example.com", nil)
	s.Nil(err)
	err = client.checksumChunk([]byte("hello world"), req)
	s.Nil(err)

	s.EqualValues("sha256 Yjk0ZDI3Yjk5MzRkM2UwOGE1MmU1MmQ3ZGE3ZGFiZmFjNDg0ZWZlMzdhNTM4MGVlOTA4OGY3YWNlMmVmY2RlOQ==", req.Header.Get("Upload-Checksum"))
}

func (s *UploadTestSuite) TestMd5ChecksumChunk() {
	client, err := NewClient(s.url, nil)
	s.Nil(err)

	client.Config.ChecksumAlgorithm = MD5

	req, _ := http.NewRequest("POST", "https://example.com", nil)
	s.Nil(err)
	err = client.checksumChunk([]byte("hello world"), req)
	s.Nil(err)

	s.EqualValues("md5 XrY7u+Ae7tCTyyK7j1rNww==", req.Header.Get("Upload-Checksum"))
}

func (s *UploadTestSuite) TestMd5HexChecksumChunk() {
	client, err := NewClient(s.url, nil)
	s.Nil(err)

	client.Config.ChecksumAlgorithm = MD5_HEX

	req, _ := http.NewRequest("POST", "https://example.com", nil)
	s.Nil(err)
	err = client.checksumChunk([]byte("hello world"), req)
	s.Nil(err)

	s.EqualValues("md5 NWViNjNiYmJlMDFlZWVkMDkzY2IyMmJiOGY1YWNkYzM=", req.Header.Get("Upload-Checksum"))
}

func (s *UploadTestSuite) TestSetSha256ChecksumAlgorithm() {
	client, err := NewClient(s.url, nil)
	s.Nil(err)

	client.Config.ChecksumAlgorithm = SHA256

	upload := NewUploadFromBytes([]byte("1234567890"))
	s.Nil(err)

	uploader, err := client.CreateUpload(upload)
	s.Nil(err)
	s.NotNil(uploader)

	err = uploader.Upload()
	s.Nil(err)

	//TODO: currently we cannot evaluate the checksum on server-side since tusd doesn't support this extension yet
	getUpload, err := s.store.GetUpload(nil, uploadIdFromUrl(uploader.url))
	s.Nil(err)

	fi, err := getUpload.GetInfo(nil)
	s.Nil(err)

	s.EqualValues(10, fi.Size)
}

func (s *UploadTestSuite) TestSetSha1ChecksumAlgorithm() {
	client, err := NewClient(s.url, nil)
	s.Nil(err)

	client.Config.ChecksumAlgorithm = SHA1

	upload := NewUploadFromBytes([]byte("1234567890"))
	s.Nil(err)

	uploader, err := client.CreateUpload(upload)
	s.Nil(err)
	s.NotNil(uploader)

	err = uploader.Upload()
	s.Nil(err)

	//TODO: currently we cannot evaluate the checksum on server-side since tusd doesn't support this extension yet
	getUpload, err := s.store.GetUpload(nil, uploadIdFromUrl(uploader.url))
	s.Nil(err)

	fi, err := getUpload.GetInfo(nil)
	s.Nil(err)

	s.EqualValues(10, fi.Size)
}

func (s *UploadTestSuite) TestConcurrentUploads() {
	var wg sync.WaitGroup

	client, err := NewClient(s.url, nil)
	s.Nil(err)

	for i := 0; i < 20; i++ {
		wg.Add(1)

		go func() {
			defer wg.Done()

			file := fmt.Sprintf("%s/%d", os.TempDir(), time.Now().UnixNano())

			f, err := os.Create(file)
			s.Nil(err)

			defer f.Close()

			err = f.Truncate(1048576 * 5) // 5 MB
			s.Nil(err)

			upload, err := NewUploadFromFile(f)
			s.Nil(err)

			uploader, err := client.CreateUpload(upload)
			s.Nil(err)
			s.NotNil(uploader)

			err = uploader.Upload()
			s.Nil(err)

			getUpload, err := s.store.GetUpload(nil, uploadIdFromUrl(uploader.url))
			s.Nil(err)

			fi, err := getUpload.GetInfo(nil)
			s.Nil(err)

			s.EqualValues(1048576*5, fi.Size)
		}()
	}

	wg.Wait()
}

func (s *UploadTestSuite) TestResumeUpload() {
	file := fmt.Sprintf("%s/%d", os.TempDir(), time.Now().Unix())

	f, err := os.Create(file)
	s.Nil(err)

	defer f.Close()

	err = f.Truncate(1048576 * 150) // 150 MB
	s.Nil(err)

	cfg := &Config{
		ChunkSize:           2 * 1024 * 1024,
		Resume:              true,
		OverridePatchMethod: false,
		Store:               NewMockStore(),
		Header: map[string][]string{
			"X-Extra-Header": []string{"somevalue"},
		},
	}

	client, err := NewClient(s.url, cfg)
	s.Nil(err)

	upload, err := NewUploadFromFile(f)
	s.Nil(err)

	uploader, err := client.CreateUpload(upload)
	s.Nil(err)
	s.NotNil(uploader)

	// This will stop the first upload.
	go func() {
		time.Sleep(250 * time.Millisecond)
		uploader.Abort()
	}()

	err = uploader.Upload()
	s.Nil(err)

	s.True(uploader.aborted)

	uploader, err = client.ResumeUpload(upload)
	s.Nil(err)
	s.NotNil(uploader)

	err = uploader.Upload()
	s.Nil(err)

	getUpload, err := s.store.GetUpload(nil, uploadIdFromUrl(uploader.url))
	s.Nil(err)

	fi, err := getUpload.GetInfo(nil)
	s.Nil(err)

	s.EqualValues(1048576*150, fi.Size)
}

func TestUploadTestSuite(t *testing.T) {
	suite.Run(t, new(UploadTestSuite))
}

func uploadIdFromUrl(url string) string {
	parts := strings.Split(url, "/")
	return parts[len(parts)-1]
}
