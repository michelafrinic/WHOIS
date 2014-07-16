package net.ripe.db.whois.common.rpsl.impl;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.rpsl.IObjectType;
import net.ripe.db.whois.common.rpsl.IObjectTypeFactory;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Collection;
import java.util.List;

/**
 * Created by michel on 7/15/14.
 */
public class RipeObjectTypeFactoryTest {
    private IObjectType inetNumObjectType;
    private IObjectType inet6NumObjectType;
    private IObjectType mntnerObjectType;
    private IObjectType organisationObjectType;
    private IObjectType personObjectType;
    private IObjectType roleObjectType;
    private IObjectType myRoleObjectType;

    private IObjectTypeFactory objectTypeFactory;

    @Before
    public void init() {
        inetNumObjectType = new InetNum();
        inet6NumObjectType = new Inet6Num();
        mntnerObjectType = new Mntner();
        organisationObjectType = new Organisation();
        personObjectType = new Person();
        roleObjectType = new Role();

        myRoleObjectType = new MyRoleObjectType();

        List<IObjectType> objectTypeList = Lists.newArrayList(inetNumObjectType, inet6NumObjectType, mntnerObjectType, organisationObjectType, personObjectType, roleObjectType);
        objectTypeFactory = new RipeObjectTypeFactory(objectTypeList);

    }

    @Test
    public void testValues() {
        Collection<IObjectType> values = objectTypeFactory.values();
        Assert.assertEquals(6, values.size());

        Assert.assertTrue(values.contains(inetNumObjectType));
        Assert.assertTrue(values.contains(inet6NumObjectType));
        Assert.assertTrue(values.contains(mntnerObjectType));
        Assert.assertTrue(values.contains(organisationObjectType));
        Assert.assertTrue(values.contains(personObjectType));
        Assert.assertTrue(values.contains(roleObjectType));
    }

    @Test
    public void testGetByClass() {
        IObjectType objectType = objectTypeFactory.get(MyRoleObjectType.class);
        Assert.assertNull(objectType);

        objectType = objectTypeFactory.get((Class) null);
        Assert.assertNull(objectType);

        objectType = objectTypeFactory.get(Role.class);
        Assert.assertEquals(objectType, roleObjectType);

        objectType = objectTypeFactory.get(IObjectType.class);
        Assert.assertNull(objectType);
    }

    @Test
    public void testGetById() {
        IObjectType objectType = objectTypeFactory.get(18);
        Assert.assertEquals(objectType, organisationObjectType);
    }

    @Test
    public void testGetByName() {
        IObjectType objectType = objectTypeFactory.get("person");
        Assert.assertEquals(objectType, personObjectType);
    }

    class MyRoleObjectType extends Role {
        @Override
        public String getName() {
            return "this is me !!";
        }

        @Override
        public String getShortName() {
            return "disizmi";
        }

        @Override
        public boolean isSet() {
            return false;
        }

        @Override
        public String getDocumentation() {
            return "blah blah";
        }

        @Override
        public int getId() {
            return 12345;
        }
    }
}