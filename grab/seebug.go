package grab

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/chromedp"
	"github.com/imroc/req/v3"
	"github.com/kataras/golog"
)

var (
	instance      context.Context
	once          sync.Once
	instanceMutex sync.Mutex
)

// TODO: 这个函数可能有bug，资源不一定释放掉 加个err
func NewChromedpInstance() context.Context {
	once.Do(func() {
		instanceMutex.Lock()
		defer instanceMutex.Unlock()

		userDataDir, err := ioutil.TempDir("", "chromedp_example")
		if err != nil {
			log.Fatal(err)
		}
		opts := append(chromedp.DefaultExecAllocatorOptions[:],
			chromedp.NoFirstRun,
			chromedp.NoDefaultBrowserCheck,
			chromedp.Flag("headless", true), // 设置为false以取消无头模式
			chromedp.Flag("disable-gpu", true),
			chromedp.Flag("enable-automation", true),
			chromedp.Flag("disable-extensions", true),
			chromedp.Flag("disable-dev-shm-usage", true),
			chromedp.Flag("disable-software-rasterizer", true),
			chromedp.Flag("disable-popup-blocking", true),
			chromedp.Flag("disable-blink-features", "AutomationControlled"),
			chromedp.UserDataDir(""),
			chromedp.UserDataDir(userDataDir),
			chromedp.UserAgent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/89.0.4389.82 Safari/537.36"),
		)
		allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
		ctx, cancel := chromedp.NewContext(allocCtx, chromedp.WithLogf(log.Printf))
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		instance = ctx
		// 在程序退出时取消context
		go func() {
			<-ctx.Done()
			cancel()
			os.RemoveAll(userDataDir)
		}()
	})

	return instance
}

type SeeBugCrawler struct {
	client *req.Client
	log    *golog.Logger
}

func NewSeeBugCrawler() Grabber {
	client := NewHttpClient()
	return &SeeBugCrawler{
		client: client,
		log:    golog.Child("[seebug-avd]"),
	}
}
func (a *SeeBugCrawler) ProviderInfo() *Provider {
	return &Provider{
		Name:        "seebug-avd",
		DisplayName: "seebug",
		Link:        "https://www.seebug.org/vuldb/vulnerabilities",
	}
}
func (a *SeeBugCrawler) GetPageCount(ctx context.Context, _ int) (int, error) {
	u := `https://www.seebug.org/vuldb/vulnerabilities`
	instance := NewChromedpInstance()
	var page_count []*cdp.Node
	err := chromedp.Run(instance,
		chromedp.Navigate(u),
		chromedp.WaitVisible(`/html/body/div[2]/div/div/div/div/table/tbody/tr[*]/td[4]/a`, chromedp.BySearch),
		chromedp.Nodes(`/html/body/div[2]/div/div/nav/ul/li[last()-1]/a/text()`, &page_count, chromedp.BySearch),
	)
	if err != nil {
		return 0, err
	}
	results := page_count[0].NodeValue
	return strconv.Atoi(results)
}

func (a *SeeBugCrawler) ParsePage(ctx context.Context, page, _ int) (chan *VulnInfo, error) {
	u := fmt.Sprintf("https://www.seebug.org/vuldb/vulnerabilities?page=%d", page)
	a.log.Infof("parsing page %s", u)
	// resp, err := a.client.R().SetContext(ctx).Get(u)
	instance = NewChromedpInstance()
	var nodes []*cdp.Node
	err := chromedp.Run(instance,
		chromedp.Navigate("https://www.seebug.org/vuldb/vulnerabilities"),
		chromedp.WaitVisible(`/html/body/div[2]/div/div/div/div/table/tbody/tr[*]/td[4]/a`, chromedp.BySearch),
		chromedp.Nodes(`/html/body/div[2]/div/div/div/div/table/tbody/tr[*]/td[4]/a`, &hrefs, chromedp.BySearch),
	)
	if err != nil {
		a.log.Error("parsing page error")
		return nil, err
	}
	var hrefs []string
	for _, node := range nodes {
		href := node.AttributeValue("href")
		if href != "" {
			hrefs = append(hrefs, href)
		}
	}
	results := make(chan *VulnInfo, 1)
	go func() {
		defer close(results)
		for _, href := range hrefs {
			select {
			case <-ctx.Done():
				return
			default:
			}
			base, _ := url.Parse("https://www.seebug.org/")
			uri, err := url.ParseRequestURI(href)
			if err != nil {
				a.log.Errorf("%s", err)
				return
			}
			vulnLink := base.ResolveReference(uri).String()
			avdInfo, err := a.parseSingle(ctx, vulnLink)
			if err != nil {
				a.log.Errorf("%s %s", err, vulnLink)
				return
			}
			results <- avdInfo
		}
	}()

	return results, nil
}

func (a *SeeBugCrawler) IsValuable(info *VulnInfo) bool {
	return info.Severity == High || info.Severity == Critical
}

func (a *SeeBugCrawler) parseSingle(ctx context.Context, vulnLink string) (*VulnInfo, error) {
	a.log.Debugf("parsing vuln %s", vulnLink)
	// resp, err := a.client.R().SetContext(ctx).Get(vulnLink)
	instance = NewChromedpInstance()

	var title_node []*cdp.Node
	var description_node []*cdp.Node
	var cveID_node []*cdp.Node
	var level_node []*cdp.Node
	var disclosure_node []*cdp.Node
	var avd_node []*cdp.Node
	var refs_node []*cdp.Node
	var tags_node []*cdp.Node

	err := chromedp.Run(instance,
		chromedp.Navigate(vulnLink),
		chromedp.WaitVisible(`//*[@id="j-vul-title"]/span`, chromedp.BySearch),
		chromedp.Nodes(`//*[@id="j-vul-title"]/span/text()`, &title_node, chromedp.BySearch),
		chromedp.Nodes(`//*[@id="j-affix-target"]/div[2]/div[1]/section[2]/div[2]/div[2]/p[2]/text()`, &description_node, chromedp.BySearch),
		chromedp.Nodes(`//*[@id="j-vul-basic-info"]/div/div[3]/dl[1]/dd/a/text()`, &cveID_node, chromedp.BySearch),
		chromedp.Nodes(`//*[@id="j-vul-basic-info"]/div/div[1]/dl[4]/dd/div`, &level_node, chromedp.BySearch), // 解析 data-original-title
		chromedp.Nodes(`//*[@id="j-vul-basic-info"]/div/div[3]/dl[1]/dd/a/text()`, &cveID_node, chromedp.BySearch),
		chromedp.Nodes(`//*[@id="j-vul-basic-info"]/div/div[1]/dl[3]/dd/text()`, &disclosure_node, chromedp.BySearch),
		chromedp.Nodes(`//*[@id="j-vul-basic-info"]/div/div[1]/dl[1]/dd/a/text()`, &avd_node, chromedp.BySearch),
		chromedp.Nodes(`//*[@id="j-affix-target"]/div[2]/div[1]/section[4]/div/div/div/ul/li[*]/a/text()`, &refs_node, chromedp.BySearch),
		chromedp.Nodes(`//*[@id="j-vul-basic-info"]/div/div[2]/dl[1]/dd/a/text()`, &tags_node, chromedp.BySearch),
	)

	if err != nil {
		panic(err)
	}
	//TODO： 继续解析

	title := ""
	description := ""
	fixSteps := ""
	level := ""
	cveID := ""
	disclosure := ""
	avd := ""
	var refs []string

	title = title_node[0].NodeValue
	description = description_node[0].NodeValue
	level = level_node[0].AttributeValue("data-original-title")
	cveID = cveID_node[0].NodeValue
	disclosure = disclosure_node[0].NodeValue
	avd = avd_node[0].NodeValue
	for _, ref := range refs_node {
		ref_link := ref.NodeValue
		if ref_link != "" {
			refs = append(refs, ref_link)
		}
	}

	severity := Low
	switch level {
	case "低危":
		severity = Low
	case "中危":
		severity = Medium
	case "高危":
		severity = High
	case "严重":
		severity = Critical
	}

	data := &VulnInfo{
		UniqueKey:   avd,
		Title:       title,
		Description: description,
		Severity:    severity,
		CVE:         cveID,
		Disclosure:  disclosure,
		References:  refs,
		Solutions:   fixSteps,
		From:        vulnLink,
		Creator:     a,
	}
	return data, nil
}
