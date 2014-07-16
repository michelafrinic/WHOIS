package net.afrinic.db.whois.common.rpsl.impl;

import com.google.common.collect.Lists;
import net.ripe.db.whois.common.rpsl.IObjectType;
import net.ripe.db.whois.common.rpsl.IObjectTypeFactory;
import net.ripe.db.whois.common.rpsl.impl.*;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import java.util.Collection;
import java.util.List;

/**
 * Created by michel on 7/15/14.
 */
public class AfrinicObjectTypeFactoryTest {
    private IObjectType inetNumObjectType;
    private IObjectType inet6NumObjectType;
    private IObjectType mntnerObjectType;
    private IObjectType organisationObjectType;
    private IObjectType personObjectType;
    private IObjectType roleObjectType;
    private IObjectType myRoleObjectType;
    private IObjectType myNewRoleObjectType;

    private IObjectTypeFactory afrinicObjectTypeFactory;
    private IObjectTypeFactory ripeObjectTypeFactory;

    @Before
    public void init() {
        inetNumObjectType = new InetNum();
        inet6NumObjectType = new Inet6Num();
        mntnerObjectType = new Mntner();
        organisationObjectType = new Organisation();
        personObjectType = new Person();
        roleObjectType = new Role();

        myRoleObjectType = new MyRoleObjectType();
        myNewRoleObjectType = new MyNewRoleObjectType();

        List<IObjectType> objectTypeList = Lists.newArrayList(inetNumObjectType, roleObjectType, inet6NumObjectType, mntnerObjectType, personObjectType, myNewRoleObjectType, organisationObjectType, myRoleObjectType);
        afrinicObjectTypeFactory = new AfrinicObjectTypeFactory(objectTypeList);
        ripeObjectTypeFactory = new RipeObjectTypeFactory(objectTypeList);
    }

    @Test
    public void testRipeValues() {
        Collection<IObjectType> values = ripeObjectTypeFactory.values();
        Assert.assertEquals(8, values.size());

        Assert.assertTrue(values.contains(inetNumObjectType));
        Assert.assertTrue(values.contains(inet6NumObjectType));
        Assert.assertTrue(values.contains(mntnerObjectType));
        Assert.assertTrue(values.contains(organisationObjectType));
        Assert.assertTrue(values.contains(personObjectType));
        Assert.assertTrue(values.contains(roleObjectType));
        Assert.assertTrue(values.contains(myRoleObjectType));
        Assert.assertTrue(values.contains(myNewRoleObjectType));
    }

    @Test
    public void testAfrinicValues() {
        Collection<IObjectType> values = afrinicObjectTypeFactory.values();
        Assert.assertEquals(8, values.size());

        Assert.assertTrue(values.contains(inetNumObjectType));
        Assert.assertTrue(values.contains(inet6NumObjectType));
        Assert.assertTrue(values.contains(mntnerObjectType));
        Assert.assertTrue(values.contains(organisationObjectType));
        Assert.assertTrue(values.contains(personObjectType));
        Assert.assertTrue(values.contains(roleObjectType));
        Assert.assertTrue(values.contains(myRoleObjectType));
        Assert.assertTrue(values.contains(myNewRoleObjectType));
    }

    @Test
    public void testRipeObjectFactory() {
        IObjectType objectType = ripeObjectTypeFactory.get(Role.class);
        Assert.assertNotEquals(objectType, myNewRoleObjectType);
        Assert.assertEquals(objectType, roleObjectType);

        objectType = ripeObjectTypeFactory.get(MyRoleObjectType.class);
        Assert.assertNotEquals(objectType, myNewRoleObjectType);
        Assert.assertEquals(objectType, myRoleObjectType);

        objectType = ripeObjectTypeFactory.get(MyNewRoleObjectType.class);
        Assert.assertEquals(objectType, myNewRoleObjectType);

        objectType = ripeObjectTypeFactory.get(Person.class);
        Assert.assertEquals(objectType, personObjectType);
    }

    @Test
    public void testAfrinicObjectFactory() {
        IObjectType objectType = afrinicObjectTypeFactory.get(Role.class);
        Assert.assertEquals(objectType, myNewRoleObjectType);

        objectType = afrinicObjectTypeFactory.get(MyRoleObjectType.class);
        Assert.assertEquals(objectType, myNewRoleObjectType);

        objectType = afrinicObjectTypeFactory.get(MyNewRoleObjectType.class);
        Assert.assertEquals(objectType, myNewRoleObjectType);

        objectType = afrinicObjectTypeFactory.get(Person.class);
        Assert.assertEquals(objectType, personObjectType);
    }

    @Test
    public void testGetInterfaceClass() {
        IObjectType objectType = afrinicObjectTypeFactory.get(IObjectType.class);
        Assert.assertNull(objectType);
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

    class MyNewRoleObjectType extends MyRoleObjectType {
        @Override
        public String getName() {
            return "this is me, NEW !!";
        }

        @Override
        public String getShortName() {
            return "disizminu";
        }

        @Override
        public boolean isSet() {
            return true;
        }

        @Override
        public String getDocumentation() {
            return "blah blah gdlgdkfdlk";
        }

        @Override
        public int getId() {
            return 123456789;
        }
    }
}