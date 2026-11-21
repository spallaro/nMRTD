using nMRTD.Cert;
using static nMRTD.Cert.CVCAuthorizationTemplate;

namespace nMRTD.Tests.Jmrtd.Cert;

/// <summary>Port of JMRTD's <c>org.jmrtd.cert.CVCAuthorizationTemplateTest</c>.</summary>
/// <remarks>
/// Not ported: <c>testPermissionImplicationReflexive</c>, as nMRTD's <c>Permission</c> is a plain enum
/// without JMRTD's <c>implies</c> method.
/// </remarks>
public class CVCAuthorizationTemplateTest
{
    [Fact]
    public void testCVCAuthorizationTemplate()
    {
        foreach (Role role in Enum.GetValues<Role>())
        {
            foreach (Permission permission in Enum.GetValues<Permission>())
            {
                CheckCVCAuthorizationTemplate(role, permission);
            }
        }
    }

    private static void CheckCVCAuthorizationTemplate(Role role, Permission accessRight)
    {
        var template = new CVCAuthorizationTemplate(role, accessRight);
        Assert.Equal(role, template.AuthorizationRole);
        Assert.Equal(accessRight, template.AccessRight);
    }
}
