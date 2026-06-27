package vkauth

import (
	"context"
	"fmt"

	"github.com/samosvalishe/free-turn-proxy/internal/provider/vk/internal/browserprofile"

	tlsclient "github.com/bogdanfinn/tls-client"
)

// subscribeToQueueData хранит параметры очереди сигналинга, полученные от VK.
type subscribeToQueueData struct {
	Key  string
	Ts   string
	Wait int
}

// fetchSubscribeToQueue - шаг 5 цепочки: вызывает calls.subscribeToQueue
// для регистрации участника в сигнальной очереди звонка.
func (c *Client) fetchSubscribeToQueue(
	ctx context.Context,
	httpClient tlsclient.HttpClient,
	profile browserprofile.Profile,
	streamID int,
	token2, apiVersion string,
	dom domainSet,
) (*subscribeToQueueData, error) {
	urlAddr := fmt.Sprintf("https://"+dom.APIDomain+"/method/calls.subscribeToQueue?v=%s", apiVersion)
	data := fmt.Sprintf("access_token=%s&wait=25", token2)

	resp, err := c.doRequest(ctx, httpClient, profile, data, urlAddr, dom)
	if err != nil {
		return nil, err
	}

	c.log.Debugf("[STREAM %d] [VK Auth] calls.subscribeToQueue response: %v", streamID, resp)

	respMap, ok := resp["response"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected subscribeToQueue response: %v", resp)
	}

	key, _ := respMap["key"].(string)
	ts, _ := respMap["ts"].(string)
	wait, _ := respMap["wait"].(float64)

	if key == "" {
		return nil, fmt.Errorf("missing key in subscribeToQueue response: %v", resp)
	}

	return &subscribeToQueueData{Key: key, Ts: ts, Wait: int(wait)}, nil
}
