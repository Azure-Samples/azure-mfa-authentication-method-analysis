---
page_type: sample
languages:
- powershell
products:
- azure-active-directory
description: "Analyses Azure AD users to make recommendations on how to improve each user's MFA configuration."
urlFragment: "azure-mfa-authentication-method-analysis"
---

# Script for Azure MFA authentication method analysis

This sample script analyses Azure AD users to make recommendations on how to improve each user's MFA configuration.

You can target a group by *ObjectId* or analyse all users in a tenant. The following user-specific location information can be targeted: UPN domain, usage location and country. You can also produce a date and time stamped CSV report of per user recommendations.

Use `-Verbose` for insight into the script's activities.

## Limitations and requirements

* You can't use a guest (B2B) account to run this script against the target tenant. The script will execute in the guest's home tenant, not the target tenant.
* Ensure you run the script with an account that can enumerate user properties. For least privilege use the User Administrator role.

## Examples

Creates per user recommendations for all users in the target tenant and displays the results to screen:

```powershell
.\MfaAuthMethodAnalysis.ps1 -TenantId 9959f32b-837b-41db-b6e5-32277e344292
```

Creates per user recommendations for each user in the target group and displays the results to screen:

```powershell
.\MfaAuthMethodAnalysis.ps1 -TenantId 9959f32b-837b-41db-b6e5-32277e344292 -TargetGroup 6424cd24-ee16-472f-bad6-85427c9febc2
```

Creates a date and time stamped CSV file in the scripts execution directory with per user recommendations for all users in the tenant. Has verbose notation to screen:

```powershell
.\MfaAuthMethodAnalysis.ps1 -TenantId 9959f32b-837b-41db-b6e5-32277e344292 -CsvOutput -Verbose
```

Creates a date and time stamped CSV file in the scripts execution directory with per user recommendations for all users in the tenant. Includes location information: UPN domain, usage location and country:

```powershell
.\MfaAuthMethodAnalysis.ps1 -TenantId 9959f32b-837b-41db-b6e5-32277e344292 -LocationInfo -CsvOutput
```

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.opensource.microsoft.com.

When you submit a pull request, a CLA bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., status check, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
