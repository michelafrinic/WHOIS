package net.ripe.db.whois.common;

import org.codehaus.jackson.JsonParseException;
import org.codehaus.jackson.map.JsonMappingException;
import org.junit.Test;

import java.io.EOFException;
import java.io.IOException;
import java.util.Map;
import java.util.regex.Pattern;

import static org.junit.Assert.*;

/**
 * Created by yogesh on 6/12/14.
 */
public class PropertyConverterTest {

    private PropertyConverter subject = new PropertyConverter();

    @Test(expected=EOFException.class)
    public void json_to_map_eof_exception() throws IOException {
        subject.jsonToPropertyMap("");
    }

    @Test(expected=JsonParseException.class)
    public void json_to_map_io_exception_1() throws IOException {
        subject.jsonToPropertyMap("value");
    }

    @Test(expected=JsonMappingException.class)
    public void json_to_map_io_exception_2() throws IOException {
        subject.jsonToPropertyMap("\"value\"");
    }

    @Test(expected=JsonParseException.class)
    public void json_to_map_io_exception_3() throws IOException {
        subject.jsonToPropertyMap("{");
    }

    @Test
    public void json_to_empty_map() throws IOException {
        Map<String,String> actualMap = subject.jsonToPropertyMap("{}");

        assertTrue(actualMap.isEmpty());
        assertEquals(0, actualMap.keySet().size());
        assertEquals(0, actualMap.values().size());
        assertEquals(null, actualMap.get("key3"));
    }

    @Test
    public void json_to_map() throws IOException {
        Map<String,String> actualMap = subject.jsonToPropertyMap(
                "{" +
                "  \"key1\":\"value 1\"," +
                "  \"key2\":\"value 2\"" +
                "}");

        assertFalse(actualMap.isEmpty());
        assertEquals(2, actualMap.keySet().size());
        assertEquals(2, actualMap.values().size());
        assertEquals("value 2", actualMap.get("key2"));
        assertEquals("value 1", actualMap.get("key1"));
        assertEquals(null, actualMap.get("key3"));
    }


    @Test
    public void string_to_pattern_null_1() {
        Pattern actualPattern = subject.stringToPattern(null);

        assertNull(actualPattern);
    }

    @Test
    public void string_to_pattern_null_2() {
        Pattern actualPattern = subject.stringToPattern("");

        assertNull(actualPattern);
    }

    @Test
    public void string_to_pattern() {
        Pattern actualPattern = subject.stringToPattern("^stop$");

        assertNotNull(actualPattern);
    }
}
