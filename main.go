package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"io/fs"
	"net/http"
	"os"
	"sort"
	"strings"

	"github.com/google/go-github/v45/github"
	"github.com/sagernet/sing-box/common/geosite"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sirupsen/logrus"
	"github.com/v2fly/v2ray-core/v5/app/router/routercommon"
	"google.golang.org/protobuf/proto"
)

var githubClient *github.Client

func init() {
	accessToken, loaded := os.LookupEnv("ACCESS_TOKEN")
	if !loaded {
		githubClient = github.NewClient(nil)
		return
	}
	transport := &github.BasicAuthTransport{
		Username: accessToken,
	}
	githubClient = github.NewClient(transport.Client())
}

func setActionOutput(name string, content string) {
	outputPath, exists := os.LookupEnv("GITHUB_OUTPUT")
	if exists {
		os.WriteFile(outputPath, []byte(name+"="+content+"\n"), fs.ModeAppend)
	}
}

func getLatestRelease(from string) (*github.RepositoryRelease, error) {
	names := strings.SplitN(from, "/", 2)
	latestRelease, _, err := githubClient.Repositories.GetLatestRelease(context.Background(), names[0], names[1])
	if err != nil {
		return nil, err
	}
	return latestRelease, err
}

func download(url *string) ([]byte, error) {
	logrus.Info("download ", *url)
	response, err := http.Get(*url)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	return io.ReadAll(response.Body)
}

func downloadGeoSite(release *github.RepositoryRelease, fileName string) ([]byte, error) {
	geositeAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == fileName
	})
	if geositeAsset == nil {
		return nil, E.New(fileName+" not found in upstream release ", release.Name)
	}
	geositeChecksumAsset := common.Find(release.Assets, func(it *github.ReleaseAsset) bool {
		return *it.Name == fileName+".sha256sum"
	})
	if geositeChecksumAsset == nil {
		return nil, E.New(fileName+".sha256sum not found in upstream release ", release.Name)
	}
	data, err := download(geositeAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	remoteChecksum, err := download(geositeChecksumAsset.BrowserDownloadURL)
	if err != nil {
		return nil, err
	}
	checksum := sha256.Sum256(data)
	if hex.EncodeToString(checksum[:]) != string(remoteChecksum[:64]) {
		return nil, E.New("checksum mismatch")
	}
	return data, nil
}

func parse(vGeositeData []byte) (map[string][]geosite.Item, error) {
	vGeositeList := routercommon.GeoSiteList{}
	err := proto.Unmarshal(vGeositeData, &vGeositeList)
	if err != nil {
		return nil, err
	}
	domainMap := make(map[string][]geosite.Item)
	for _, vGeositeEntry := range vGeositeList.Entry {
		code := strings.ToLower(vGeositeEntry.CountryCode)
		domains := make([]geosite.Item, 0, len(vGeositeEntry.Domain)*2)
		attributes := make(map[string][]*routercommon.Domain)
		for _, domain := range vGeositeEntry.Domain {
			if len(domain.Attribute) > 0 {
				for _, attribute := range domain.Attribute {
					attributes[attribute.Key] = append(attributes[attribute.Key], domain)
				}
			}
			switch domain.Type {
			case routercommon.Domain_Plain:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainKeyword,
					Value: domain.Value,
				})
			case routercommon.Domain_Regex:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainRegex,
					Value: domain.Value,
				})
			case routercommon.Domain_RootDomain:
				if strings.Contains(domain.Value, ".") {
					domains = append(domains, geosite.Item{
						Type:  geosite.RuleTypeDomain,
						Value: domain.Value,
					})
				}
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomainSuffix,
					Value: "." + domain.Value,
				})
			case routercommon.Domain_Full:
				domains = append(domains, geosite.Item{
					Type:  geosite.RuleTypeDomain,
					Value: domain.Value,
				})
			}
		}
		domainMap[code] = common.Uniq(domains)
		for attribute, attributeEntries := range attributes {
			attributeDomains := make([]geosite.Item, 0, len(attributeEntries)*2)
			for _, domain := range attributeEntries {
				switch domain.Type {
				case routercommon.Domain_Plain:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainKeyword,
						Value: domain.Value,
					})
				case routercommon.Domain_Regex:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainRegex,
						Value: domain.Value,
					})
				case routercommon.Domain_RootDomain:
					if strings.Contains(domain.Value, ".") {
						attributeDomains = append(attributeDomains, geosite.Item{
							Type:  geosite.RuleTypeDomain,
							Value: domain.Value,
						})
					}
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomainSuffix,
						Value: "." + domain.Value,
					})
				case routercommon.Domain_Full:
					attributeDomains = append(attributeDomains, geosite.Item{
						Type:  geosite.RuleTypeDomain,
						Value: domain.Value,
					})
				}
			}
			domainMap[code+"@"+attribute] = common.Uniq(attributeDomains)
		}
	}
	return domainMap, nil
}

func generateDomainList(domainMap map[string][]geosite.Item, outputFileName string) error {
	outputFile, err := os.Create(outputFileName)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	var list []string
	for key := range domainMap {
		list = append(list, key)
	}
	sort.Strings(list)

	_, err = outputFile.WriteString(strings.Join(list, "\n"))

	return err
}

func generateGeoSite(release *github.RepositoryRelease, inputFileName string, outputFileName string) error {
	vData, err := downloadGeoSite(release, inputFileName)
	if err != nil {
		return err
	}

	outputFile, err := os.Create(outputFileName)
	if err != nil {
		return err
	}
	defer outputFile.Close()

	domainMap, err := parse(vData)
	if err != nil {
		return err
	}

	err = generateDomainList(domainMap, strings.Split(outputFileName, ".")[0]+".txt")
	if err != nil {
		return err
	}

	return geosite.Write(outputFile, domainMap)
}

func main() {
	fullSource := "Loyalsoldier/v2ray-rules-dat"
	fullInput := "geosite.dat"
	fullOutput := "geosite-full.db"

	liteSource := "v2fly/domain-list-community"
	liteInput := "dlc.dat"
	liteOutput := "geosite-lite.db"

	destination := "yvvw/sing-geosite"

	fullSourceRelease, err := getLatestRelease(fullSource)
	if err != nil {
		logrus.Fatal(err)
	}
	liteSourceRelease, err := getLatestRelease(liteSource)
	if err != nil {
		logrus.Fatal(err)
	}
	destinationRelease, err := getLatestRelease(destination)
	if err != nil {
		logrus.Warn("missing destination latest release")
	} else {
		if os.Getenv("NO_SKIP") != "true" && strings.Contains(*destinationRelease.Name, *fullSourceRelease.Name) {
			logrus.Info("already latest")
			setActionOutput("skip", "true")
			return
		}
	}

	err = generateGeoSite(fullSourceRelease, fullInput, fullOutput)
	if err != nil {
		logrus.Fatal(err)
	}
	err = generateGeoSite(liteSourceRelease, liteInput, liteOutput)
	if err != nil {
		logrus.Fatal(err)
	}
	tagName := *fullSourceRelease.Name
	setActionOutput("tag", tagName[12:])
}
