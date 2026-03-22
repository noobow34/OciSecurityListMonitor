using Amazon.Lambda.Core;
using Oci.Common;
using Oci.Common.Auth;
using Oci.CoreService;
using Oci.CoreService.Models;
using Oci.CoreService.Requests;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

[assembly: LambdaSerializer(
    typeof(Amazon.Lambda.Serialization.SystemTextJson.DefaultLambdaJsonSerializer))]

namespace OciSecurityListMonitor;

public class Function
{
    private static readonly HttpClient _httpClient = new();

    private static readonly string SUBNET_ID = Environment.GetEnvironmentVariable("OCI_SUBNET_ID") ?? throw new InvalidOperationException("OCI_SUBNET_ID is not set");
    private static readonly string COMPONET_ID = Environment.GetEnvironmentVariable("OCI_COMPARTMENT_ID") ?? throw new InvalidOperationException("OCI_COMPARTMENT_ID is not set");
    private static readonly string USER_ID = Environment.GetEnvironmentVariable("OCI_USER_ID") ?? throw new InvalidOperationException("OCI_USER_ID is not set");
    private static readonly string FINGERPRINT = Environment.GetEnvironmentVariable("OCI_FINGERPRINT") ?? throw new InvalidOperationException("OCI_FINGERPRINT is not set");
    private static readonly string TENANCY_ID = Environment.GetEnvironmentVariable("OCI_TENANCY_ID") ?? throw new InvalidOperationException("OCI_TENANCY_ID is not set");
    private static readonly string PRIVATE_KEY = Environment.GetEnvironmentVariable("OCI_PRIVATE_KEY") ?? throw new InvalidOperationException("OCI_PRIVATE_KEY is not set");

    public async Task FunctionHandler(ILambdaContext context)
    {
        var logger = context.Logger;
        logger.LogInformation("SSH監視Lambda開始");

        var provider = new SimpleAuthenticationDetailsProvider
        {
            UserId = USER_ID,
            Fingerprint = FINGERPRINT,
            TenantId = TENANCY_ID,
            Region = Oci.Common.Region.AP_TOKYO_1,
            PrivateKeySupplier = new StringPrivateKeySupplier(PRIVATE_KEY)
        };

        var vcClient = new VirtualNetworkClient(provider);

        // 期限切れのセキュリティリストを取得
        List<SecurityList> expiredLists;
        try
        {
            expiredLists = await GetExpiredSecurityListsAsync(vcClient, logger);
        }
        catch (Exception ex)
        {
            logger.LogError($"セキュリティリスト取得失敗: {ex.Message}");
            throw;
        }

        if (expiredLists.Count == 0)
        {
            logger.LogInformation("期限切れのセキュリティリストなし。正常終了。");
            return;
        }

        logger.LogWarning($"期限切れのセキュリティリスト検知: {expiredLists.Count}件");

        foreach (var secList in expiredLists)
        {
            logger.LogWarning($"対象: {secList.DisplayName} / ID: {secList.Id}");

            Exception? deleteError = null;

            try
            {
                await DeleteSecurityListAsync(vcClient, secList, logger);
            }
            catch (Exception ex)
            {
                deleteError = ex;
                logger.LogError($"セキュリティリスト削除失敗 ({secList.DisplayName}): {ex.Message}");
            }

            try
            {
                await NotifySlackAsync(secList, deleteError, logger);
            }
            catch (Exception ex)
            {
                logger.LogError($"Slack通知失敗 ({secList.DisplayName}): {ex.Message}");
            }
        }

        logger.LogInformation("SSH監視Lambda終了");
    }

    /// <summary>
    /// purpose=temp-ssh-open かつ expires_at が過去のセキュリティリストを返す
    /// </summary>
    private async Task<List<SecurityList>> GetExpiredSecurityListsAsync(
        VirtualNetworkClient client, ILambdaLogger logger)
    {
        var result = new List<SecurityList>();
        string? nextPage = null;

        do
        {
            var request = new ListSecurityListsRequest
            {
                CompartmentId = COMPONET_ID,
                Page = nextPage,
                Limit = 100,
            };

            var response = await client.ListSecurityLists(request);

            foreach (var sl in response.Items)
            {
                if (!sl.FreeformTags.TryGetValue("purpose", out var purpose)
                    || purpose != "temp-ssh-open")
                    continue;

                if (!sl.FreeformTags.TryGetValue("expires_at", out var expiresAtStr))
                    continue;

                if (!DateTimeOffset.TryParse(expiresAtStr, out var expiresAt))
                {
                    logger.LogWarning(
                        $"expires_atのパース失敗: {sl.DisplayName} / 値: {expiresAtStr}");
                    continue;
                }

                if (expiresAt < DateTimeOffset.UtcNow)
                {
                    result.Add(sl);
                }
            }

            nextPage = response.OpcNextPage;

        } while (nextPage != null);

        return result;
    }

    /// <summary>
    /// セキュリティリストを削除する
    /// </summary>
    private async Task DeleteSecurityListAsync(
        VirtualNetworkClient client, SecurityList secList, ILambdaLogger logger)
    {
        logger.LogInformation($"サブネット取得: {SUBNET_ID}");
        var subnetResponse = await client.GetSubnet(new GetSubnetRequest { SubnetId = SUBNET_ID });
        var subnet = subnetResponse.Subnet;

        if (subnet.SecurityListIds.Contains(secList.Id))
        {
            subnet.SecurityListIds.Remove(secList.Id);
            await client.UpdateSubnet(new UpdateSubnetRequest
            {
                SubnetId = subnet.Id,
                UpdateSubnetDetails = new UpdateSubnetDetails { SecurityListIds = subnet.SecurityListIds },
            });
            logger.LogInformation($"サブネットからデタッチ完了: {secList.Id}");
        }
        else
        {
            logger.LogWarning($"サブネットにセキュリティリストが紐付いていません（スキップ）: {secList.Id}");
        }

        await client.DeleteSecurityList(new DeleteSecurityListRequest { SecurityListId = secList.Id });
        logger.LogInformation($"セキュリティリスト削除完了: {secList.DisplayName}");
    }

    /// <summary>
    /// Slack通知（削除成功/失敗で内容を切り替え）
    /// </summary>
    private async Task NotifySlackAsync(
        SecurityList secList, Exception? deleteError, ILambdaLogger logger)
    {
        string message;
        if (deleteError == null)
        {
            message = $":white_check_mark: *SSH開放の削除漏れを検知・自動削除しました*\n"
                    + $"• セキュリティリスト名: `{secList.DisplayName}`\n"
                    + $"• ID: `{secList.Id}`\n"
                    + $"• expires_at: `{secList.FreeformTags["expires_at"]}`";
        }
        else
        {
            message = $":fire: *SSH開放の削除漏れを検知しましたが、自動削除に失敗しました*\n"
                    + $"• セキュリティリスト名: `{secList.DisplayName}`\n"
                    + $"• ID: `{secList.Id}`\n"
                    + $"• expires_at: `{secList.FreeformTags["expires_at"]}`\n"
                    + $"• エラー: `{deleteError.Message}`";
        }

        var token = Environment.GetEnvironmentVariable("SLACK_BOT_TOKEN");
        var channelId = Environment.GetEnvironmentVariable("SLACK_CHANNEL");

        var payload = new
        {
            channel = channelId,
            text = message
        };

        _httpClient.DefaultRequestHeaders.Authorization =
            new AuthenticationHeaderValue("Bearer", token);

        var json = JsonSerializer.Serialize(payload);
        var content = new StringContent(json, Encoding.UTF8, "application/json");

        await _httpClient.PostAsync("https://slack.com/api/chat.postMessage", content);

        logger.LogInformation($"Slack通知完了: {secList.DisplayName}");
    }
}