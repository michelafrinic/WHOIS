package net.ripe.db.whois.common.iptree;

import net.ripe.db.whois.common.domain.Ipv4Resource;
import net.ripe.db.whois.common.domain.Ipv6Resource;
import org.junit.Assert;
import org.junit.Test;

import java.util.ArrayList;
import java.util.List;

/**
 * Created by michel on 6/9/14.
 */
public class ExcludedResourcesTest {

    @Test
    public void nullLists() {
        String [] excludedV4Resources = null;
        String [] excludedV6Resources = null;

        ExcludedResources excludedResources = new ExcludedResources(excludedV4Resources, excludedV6Resources);

        Assert.assertFalse(excludedResources.isExcluded((Ipv4Entry) null));
        Assert.assertFalse(excludedResources.isExcluded(new Ipv4Entry(Ipv4Resource.parse("0/0"), 1)));
        Assert.assertFalse(excludedResources.isExcluded(new Ipv4Entry(Ipv4Resource.parse("11.100.0.0/16"), 1)));

        Assert.assertFalse(excludedResources.isExcluded((Ipv6Entry) null));
        Assert.assertFalse(excludedResources.isExcluded(new Ipv6Entry(Ipv6Resource.parse("0::/0"), 1)));
        Assert.assertFalse(excludedResources.isExcluded(new Ipv6Entry(Ipv6Resource.parse("2c0f:f930::/32"), 1)));
    }

    @Test
    public void emptyLists() {
        String [] excludedV4Resources = {};
        String [] excludedV6Resources = {};

        ExcludedResources excludedResources = new ExcludedResources(excludedV4Resources, excludedV6Resources);

        Assert.assertFalse(excludedResources.isExcluded((Ipv4Entry) null));
        Assert.assertTrue(excludedResources.isExcluded(new Ipv4Entry(Ipv4Resource.parse("0/0"), 1)));
        Assert.assertFalse(excludedResources.isExcluded(new Ipv4Entry(Ipv4Resource.parse("11.100.0.0/16"), 1)));

        Assert.assertFalse(excludedResources.isExcluded((Ipv6Entry) null));
        Assert.assertTrue(excludedResources.isExcluded(new Ipv6Entry(Ipv6Resource.parse("0::/0"), 1)));
        Assert.assertFalse(excludedResources.isExcluded(new Ipv6Entry(Ipv6Resource.parse("2c0f:f930::/32"), 1)));
    }

    @Test
    public void testV4Exclusions() {
        String [] excludedV4Resources = {"196/8","197/8"};
        String [] excludedV6Resources = null;

        ExcludedResources excludedResources = new ExcludedResources(excludedV4Resources, excludedV6Resources);

        Assert.assertFalse(excludedResources.isExcluded((Ipv4Entry) null));
        Assert.assertTrue(excludedResources.isExcluded(new Ipv4Entry(Ipv4Resource.parse("0/0"), 1)));
        Assert.assertFalse(excludedResources.isExcluded(new Ipv4Entry(Ipv4Resource.parse("11.100.0.0/16"), 1)));
        Assert.assertTrue(excludedResources.isExcluded(new Ipv4Entry(Ipv4Resource.parse("196.100.15.0/24"), 1)));
        Assert.assertTrue(excludedResources.isExcluded(new Ipv4Entry(Ipv4Resource.parse("196.100.1.56"), 1)));
    }

    @Test
    public void testV4ExclusionsList() {
        String [] excludedV4Resources = {"196/8","197/8"};
        String [] excludedV6Resources = null;

        ExcludedResources excludedResources = new ExcludedResources(excludedV4Resources, excludedV6Resources);

        List<Ipv4Entry> list = new ArrayList<Ipv4Entry>();
        list.add(new Ipv4Entry(Ipv4Resource.parse("0/0"), 1));
        list.add(new Ipv4Entry(Ipv4Resource.parse("196.100.15.0/24"), 2));
        list.add(new Ipv4Entry(Ipv4Resource.parse("11.100.0.0/16"), 3));
        list.add(new Ipv4Entry(Ipv4Resource.parse("196.100.1.56"), 4));

        List<Ipv4Entry> filteredList = excludedResources.removeV4Excluded(list);

        Assert.assertEquals(filteredList.size(), 1);
        Assert.assertEquals(filteredList.get(0), new Ipv4Entry(Ipv4Resource.parse("11.100.0.0/16"), 3));
    }

    @Test
    public void testRootIsAlwaysExcluded() {
        String [] excludedV4Resources = { "196/0"}; // considered as root
        String [] excludedV6Resources = {};

        ExcludedResources excludedResources = new ExcludedResources(excludedV4Resources, excludedV6Resources);

        Assert.assertFalse(excludedResources.isExcluded((Ipv4Entry) null));
        Assert.assertTrue(excludedResources.isExcluded(new Ipv4Entry(Ipv4Resource.parse("0/0"), 1)));
        Assert.assertTrue(excludedResources.isExcluded(new Ipv4Entry(Ipv4Resource.parse("11.100.0.0/16"), 1)));
    }
}
