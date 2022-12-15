#define PCRE2_CODE_UNIT_WIDTH 8
#define EXPAT_BUFFER_LENGTH 1000

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <expat.h>
#include <pcre2.h>

#include "list.h"
#include "map.h"


int is_numeric(char *num_in) {

    int retval = 1;

    for (int i = 0; i < strlen(num_in); i++) {
        if (!isdigit(num_in[i])) {
            retval = 0;
        }
    }

    return retval;
}

Map *get_match_data(char *pattern_in, char *subject_in, size_t offset) {

    Map *match_map = map_new(2);
    List *match_list = list_new(1);

    pcre2_code *re;
    PCRE2_SPTR pattern = (PCRE2_SPTR)pattern_in;
    PCRE2_SPTR subject = (PCRE2_SPTR)subject_in;
    PCRE2_SPTR name_table;

    int errornumber;
    int rc;

    PCRE2_SIZE erroroffset;
    PCRE2_SIZE *ovector;
    PCRE2_SIZE start_offset = (PCRE2_SIZE)offset;

    size_t group_end = 0;
    size_t subject_length = strlen((char *)subject);
    pcre2_match_data *match_data;

    re = pcre2_compile(
        pattern,
        PCRE2_ZERO_TERMINATED,
        0,
        &errornumber,
        &erroroffset,
        NULL
    );

    if (re == NULL) {
        PCRE2_UCHAR buffer[256];
        pcre2_get_error_message(errornumber, buffer, sizeof(buffer));
        fprintf(
            stderr,
            "ERROR: PCRE2 compilation failed at offset %d: %s\n",
            (int)erroroffset,
            buffer
        );
        exit(1);
    }

    match_data = pcre2_match_data_create_from_pattern(re, NULL);

    rc = pcre2_match(
        re,
        subject,
        subject_length,
        offset,
        0,
        match_data,
        NULL
    );

    if (rc > 0) {

        ovector = pcre2_get_ovector_pointer(match_data);
        group_end = ovector[1];

        for (int i = 0; i < rc; i++) {

            PCRE2_SPTR substring_start = subject + ovector[2*i];
            size_t substring_length = ovector[(2*i)+1] - ovector[2*i];

            char *list_substring;
            list_substring = malloc((substring_length+1)*sizeof(char));
            memset(list_substring, '\0', (substring_length+1)*sizeof(char));
            memcpy(list_substring, (char *)substring_start, substring_length);

            list_append(match_list, list_substring);
        }
    }

    map_set(match_map, "groups", match_list);
    map_set(match_map, "group_end", &group_end);
    map_set(match_map, "matches", &rc);

    pcre2_match_data_free(match_data);
    pcre2_code_free(re);

    return match_map;
}

void free_match_data(Map *match_map) {

    List *free_groups = map_get(match_map, "groups");

    for (int i = 0; i < list_size(free_groups); i++) {
        char *group_item = (char *)list_get(free_groups, i);
        free(group_item);
    }

    list_free(free_groups);
    map_free(match_map);
}

Map *get_element_path_to_list(char *element_path_in) {

    Map *element_indexes = map_new(2);
    List *path_list = list_new(1);
    List *path_indexes = list_new(1);

    Map *match_map;
    List *match_list;

    size_t *map_offset;
    size_t offset = 0;
    int *map_matches;
    int matches;

    char *list_item;
    char *index_item;

    while (1) {

        index_item = NULL;
        
        match_map = get_match_data("<(.*?)(?:<(\\d+)>)?>", element_path_in, offset);
        map_offset = (size_t *)map_get(match_map, "group_end");
        offset = *map_offset;
        map_matches = (int *)map_get(match_map, "matches");
        matches = *map_matches;

        if (matches < 0) {
            free_match_data(match_map);
            break;
        }

        match_list = map_get(match_map, "groups");
        for (int i = 0; i < list_size(match_list); i++) {

            char *group_item = (char *)list_get(match_list, i);

            switch (i) {
                case 1:
                    list_item = group_item;
                    break;
                case 2:
                    index_item = group_item;
                    break;
            }
        }

        list_append(path_list, list_item);
        list_append(path_indexes, index_item);
    }

    map_set(element_indexes, "path_list", path_list);
    map_set(element_indexes, "path_indexes", path_indexes);

    return element_indexes;
}

void free_element_path_to_list(Map *element_list_in) {

    List *path_list = map_get(element_list_in, "path_list");
    List *path_indexes = map_get(element_list_in, "path_indexes");

    for (int i = 0; i < list_size(path_list); i++) {
        char *list_item = list_get(path_list,  i);
        free(list_item);
    }
    for (int i = 0; i < list_size(path_indexes); i++) {
        char *list_item = list_get(path_indexes, i);
        free(list_item);
    }

    list_free(path_list);
    list_free(path_indexes);
    map_free(element_list_in);
}

void append_element_dict(Map *element_dictionary_in, char *element_path_chars_in) {

    void append_element_dict_by_list(Map *element_dictionary_in, List *element_temp_path_in) {

        List *list_from_map;
        Map *map_in_list;
        char *temp_element = list_get(element_temp_path_in, 0);

        if (
            (
                map_in(
                    element_dictionary_in,
                    temp_element
                ) == 0
            ) || (
                map_get(
                    element_dictionary_in,
                    temp_element
                ) == NULL
            )
        ) {
            map_set(
                element_dictionary_in,
                temp_element,
                list_new(1)
            );
        }

        list_from_map = map_get(
            element_dictionary_in,
            temp_element
        );

        if (list_size(element_temp_path_in) <= 1) {

            map_in_list = map_new(3);

            map_set(map_in_list, "attributes", map_new(1));
            map_set(map_in_list, "character_data", list_new(1));
            map_set(map_in_list, "sub_elements", map_new(1));

            list_append(list_from_map, map_in_list);

        } else {

            int path_index = list_size(list_from_map)-1;

            map_in_list = list_get(list_from_map, path_index);

            Map *sub_element_map = map_get(map_in_list, "sub_elements");
            list_del(element_temp_path_in, 0);

            if (list_size(element_temp_path_in) > 0) {
                append_element_dict_by_list(sub_element_map, element_temp_path_in);
            }
        }
    }

    Map *element_indexes = get_element_path_to_list(element_path_chars_in);
    List *element_path_in = map_get(element_indexes, "path_list");
    List *element_path_copy = list_new(list_size(element_path_in));

    for (int i = 0; i < list_size(element_path_in); i++) {

        char *path_item = (char *)list_get(element_path_in, i);
        char *path_copy;

        path_copy = malloc((strlen(path_item)+1)*sizeof(char));
        memset(path_copy, '\0', (strlen(path_item)+1)*sizeof(char));
        memcpy(path_copy, path_item, strlen(path_item));

        list_append(element_path_copy, path_copy);
    }

    free_element_path_to_list(element_indexes);
    append_element_dict_by_list(element_dictionary_in, element_path_copy);
    list_free(element_path_copy);
}

void free_element_dict(Map *element_dictionary_in) {

    if (map_size(element_dictionary_in)) {

        for (int i = 0; i < element_dictionary_in->cap; i++) {

            char *map_key = element_dictionary_in->keys[i];
            if (map_key != NULL) {

                List *list_in_map = map_get(element_dictionary_in, map_key);

                for (int j = 0; j < list_size(list_in_map); j++) {

                    Map *map_in_list = list_get(list_in_map, j);
                    if (map_in(map_in_list, "sub_elements")) {
                        Map *sub_elements_map = map_get(map_in_list, "sub_elements");
                        free_element_dict(sub_elements_map);
                    }

                    Map *attributes_map = map_get(map_in_list, "attributes");
                    for (int k = 0; k < attributes_map->cap; k++) {
                        if (attributes_map->keys[k] != NULL) {
                            char *free_value = map_get(attributes_map, attributes_map->keys[k]);
                            free(free_value);
                        }
                    }
                    map_free(attributes_map);

                    List *character_data_list = map_get(map_in_list, "character_data");
                    for (int k = 0; k < list_size(character_data_list); k++) {
                        char *free_value = list_get(character_data_list, k);
                        free(free_value);
                    }
                    list_free(character_data_list);

                    map_free(map_in_list);
                }
                list_free(list_in_map);
            }
        }
    }
    map_free(element_dictionary_in);
}

void append_element_data(
    Map *element_dictionary_in,
    char *element_path_chars_in,
    Map *element_attributes_in,
    List *element_data_in
) {

    void append_element_data_by_list(
        Map *element_dictionary_in,
        List *element_temp_path_in,
        Map *element_attributes_in,
        List *element_data_in
    ) {

        List *list_from_map;
        size_t path_index;
        Map *map_in_list;

        List *character_data_list;
        Map *attribute_map;

        list_from_map = map_get(
            element_dictionary_in,
            (char *)list_get(element_temp_path_in, 0)
        );

        path_index = list_size(list_from_map)-1;
        map_in_list = list_get(list_from_map, path_index);

        character_data_list = map_get(map_in_list, "character_data");
        for (int i = 0; i < list_size(element_data_in); i++) {

            char *cdata_value_in = list_get(element_data_in, i);
            char *cdata_copy;

            cdata_copy = malloc((strlen(cdata_value_in)+1)*sizeof(char));
            memset(cdata_copy, '\0', (strlen(cdata_value_in)+1)*sizeof(char));
            memcpy(cdata_copy, cdata_value_in, strlen(cdata_value_in)*sizeof(char));

            list_append(character_data_list, cdata_copy);
        }

        attribute_map = map_get(map_in_list, "attributes");
        for (int i = 0; i < map_size(element_attributes_in); i++) {

            char *key_copy;
            key_copy = calloc(
                strlen(element_attributes_in->keys[i])+1,
                sizeof(char)
            );
            memcpy(
                key_copy,
                element_attributes_in->keys[i],
                strlen(element_attributes_in->keys[i])
            );

            char *attr_value_in = map_get(
                element_attributes_in,
                key_copy
            );
            char *attr_copy;

            attr_copy = malloc((strlen(attr_value_in)+1)*sizeof(char));
            memset(attr_copy, '\0', (strlen(attr_value_in)+1)*sizeof(char));
            memcpy(attr_copy, attr_value_in, strlen(attr_value_in)*sizeof(char));

            map_set(attribute_map, key_copy, attr_copy);
        }

        if (list_size(element_temp_path_in) >= 2) {
            Map *sub_element_map = map_get(map_in_list, "sub_elements");
            list_del(element_temp_path_in, 0);
            if (list_size(element_temp_path_in) > 0) {
                append_element_data_by_list(
                    sub_element_map,
                    element_temp_path_in,
                    element_attributes_in,
                    element_data_in
                );
            }
        }
    }

    Map *element_indexes = get_element_path_to_list(element_path_chars_in);
    List *element_path_in = map_get(element_indexes, "path_list");
    List *element_path_copy = list_new(list_size(element_path_in));

    for (int i = 0; i < list_size(element_path_in); i++) {

        char *path_item = (char *)list_get(element_path_in, i);
        char *path_copy;

        path_copy = malloc((strlen(path_item)+1)*sizeof(char));
        memset(path_copy, '\0', (strlen(path_item)+1)*sizeof(char));
        memcpy(path_copy, path_item, strlen(path_item));

        list_append(element_path_copy, path_copy);
    }

    free_element_path_to_list(element_indexes);
    append_element_data_by_list(
        element_dictionary_in,
        element_path_copy,
        element_attributes_in,
        element_data_in
    );
    list_free(element_path_copy);
}

void free_current_element_data(Map *current_element_data_in) {

    for (int i = 0; i < current_element_data_in->cap; i++) {

        char *map_key = current_element_data_in->keys[i]; 

        if (map_key != NULL) {
            Map *data_map = map_get(current_element_data_in, map_key);

            List *cdata_list = map_get(data_map, "cdata");
            for (int j = 0; j < list_size(cdata_list); j++) {
                char *free_value = list_get(cdata_list, j);
                free(free_value);
            }
            list_free(cdata_list);

            Map *attrs_map = map_get(data_map, "attrs");
            for (int j = 0; j < attrs_map->cap; j++) {
                if (attrs_map->keys[j] != NULL) {
                    char *free_value = map_get(attrs_map, attrs_map->keys[j]);
                    free(free_value);
                }
            }
            map_free(attrs_map);

            map_free(data_map);
        }
    }
}

Map *get_element_map(Map *element_dictionary_in, char *element_path_chars_in) {

    Map *get_element_map_by_list(
        Map *element_dictionary_in,
        List *element_temp_path_in,
        List *element_temp_indexes_in
    ) {

        List *list_from_map;
        size_t path_index;
        char *temp_index;
        Map *map_in_list;

        list_from_map = map_get(
            element_dictionary_in,
            (char *)list_get(element_temp_path_in, 0)
        );

        path_index = list_size(list_from_map)-1;
        temp_index = list_get(element_temp_indexes_in, 0);

        if (temp_index != NULL && is_numeric(temp_index)) {
            path_index = atoi(temp_index);
        }

        map_in_list = list_get(list_from_map, path_index);
        if (
            (list_size(element_temp_path_in) <= 1) &&
            (list_size(element_temp_indexes_in) <= 1)
        ) {

            return map_in_list;

        } else {

            Map *sub_element_map = map_get(map_in_list, "sub_elements");
            list_del(element_temp_path_in, 0);
            list_del(element_temp_indexes_in, 0);

            return get_element_map_by_list(
                sub_element_map,
                element_temp_path_in,
                element_temp_indexes_in
            );
        } 
    }

    Map *element_indexes = get_element_path_to_list(element_path_chars_in);
    List *element_path_in = map_get(element_indexes, "path_list");
    List *element_path_copy = list_new(list_size(element_path_in));
    List *element_indexes_in = map_get(element_indexes, "path_indexes");
    List *element_indexes_copy = list_new(list_size(element_indexes_in));

    Map *return_map;

    for (int i = 0; i < list_size(element_path_in); i++) {

        char *path_item = (char *)list_get(element_path_in, i);
        char *path_copy;

        path_copy = malloc((strlen(path_item)+1)*sizeof(char));
        memset(path_copy, '\0', (strlen(path_item)+1)*sizeof(char));
        memcpy(path_copy, path_item, strlen(path_item));

        list_append(element_path_copy, path_copy);
    }
    for (int i = 0; i < list_size(element_indexes_in); i++) {

        char *index_item = (char *)list_get(element_indexes_in, i);
        char *index_copy = NULL;


        if (index_item != NULL) {
            index_copy = malloc((strlen(index_item)+1)*sizeof(char));
            memset(index_copy, '\0', (strlen(index_item)+1)*sizeof(char));
            memcpy(index_copy, index_item, strlen(index_item));
        }

        list_append(element_indexes_copy, index_copy);
    }

    free_element_path_to_list(element_indexes);
    return_map = get_element_map_by_list(
        element_dictionary_in,
        element_path_copy,
        element_indexes_copy
    );
    list_free(element_path_copy);
    list_free(element_indexes_copy);

    return return_map;
}

Map *get_xml_map(char *xml_string) {

    typedef struct ElementStruct {
        char *element_path;
        Map *element_dictionary;
        Map *current_element_data;
    } ElementStruct;

    void start_element_handler(void *user_data_ptr, const char *name, const char **attrs) {

        ElementStruct *user_data = user_data_ptr;
        
        Map *data_map;
        Map *attrs_map = map_new(1);
        List *cdata_list = list_new(1);

        size_t new_length = strlen(user_data->element_path)+strlen(name)+2;
        char *new_path;
        char *map_path;

        new_path = realloc(user_data->element_path, (new_length+1)*sizeof(char));
        if (new_path == NULL) {
            printf("ERROR: Failed realloc()\n");
            free(user_data->element_path);
            exit(1);
        }
        sprintf(new_path, "%s<%s>", new_path, name);
        new_path[new_length] = '\0';
        user_data->element_path = new_path;

        if (!map_in(user_data->current_element_data, user_data->element_path)) {
            map_set(user_data->current_element_data, user_data->element_path, map_new(2));
        }
        data_map = map_get(user_data->current_element_data, user_data->element_path);

        for (int i = 0; attrs[i] != NULL && attrs[i+1] != NULL; i+=2) {

            char *attrs_key;
            char *attrs_value;

            attrs_key = malloc((strlen(attrs[i])+1)*sizeof(char));
            memset(attrs_key, '\0', (strlen(attrs[i])+1)*sizeof(char));
            memcpy(attrs_key, attrs[i], strlen(attrs[i]));

            attrs_value = malloc((strlen(attrs[i+1])+1)*sizeof(char));
            memset(attrs_value, '\0', (strlen(attrs[i+1])+1)*sizeof(char));
            memcpy(attrs_value, attrs[i+1], strlen(attrs[i+1]));

            map_set(attrs_map, attrs_key, attrs_value);
        }

        map_set(data_map, "attrs", attrs_map);
        map_set(data_map, "cdata", cdata_list);

        append_element_dict(user_data->element_dictionary, user_data->element_path);
    }

    void character_data_handler(void *user_data_ptr, const char *value, int len) {

        ElementStruct *user_data = user_data_ptr;

        Map *data_map = map_get(user_data->current_element_data, user_data->element_path);
        List *cdata_list = map_get(data_map, "cdata");

        char *cdata_value;

        cdata_value = malloc((len+1)*sizeof(char));
        memset(cdata_value, '\0', (len+1)*sizeof(char));
        memcpy(cdata_value, value, len*sizeof(char));

        list_append(cdata_list, cdata_value);
    }

    void end_element_handler(void *user_data_ptr, const char *name) {

        ElementStruct *user_data = user_data_ptr;

        Map *data_map = map_get(user_data->current_element_data, user_data->element_path);
        List *cdata_list = map_get(data_map, "cdata");
        Map *attrs_map = map_get(data_map, "attrs");

        char *last_element = strrchr(user_data->element_path, '<');
        char *new_path;

        append_element_data(
            user_data->element_dictionary,
            user_data->element_path,
            attrs_map,
            cdata_list
        );

        memset(last_element, '\0', strlen(last_element)*sizeof(char));
        new_path = realloc(
            user_data->element_path,
            (strlen(user_data->element_path)+1)*sizeof(char)
        );
        if (new_path == NULL) {
            printf("ERROR: Failed realloc()\n");
            free(user_data->element_path);
            exit(1);
        }
        user_data->element_path = new_path;
    }

    int buffer_len = EXPAT_BUFFER_LENGTH;

    char *xml_ptr;
    char xml_buffer[buffer_len];
    int xml_done = 0;
    char *new_ptr;

    ElementStruct *element_data = malloc(sizeof(ElementStruct));
    Map *return_map;

    element_data->element_path = malloc(sizeof(char));
    memset(element_data->element_path, '\0', sizeof(char));

    element_data->element_dictionary = map_new(1);
    element_data->current_element_data = map_new(1);

    XML_Parser parser = XML_ParserCreate(NULL);

    XML_SetElementHandler(parser, start_element_handler, end_element_handler);
    XML_SetCharacterDataHandler(parser, character_data_handler);
    XML_SetUserData(parser, element_data);

    xml_ptr = xml_string;
    while (1) {

        if (strlen(xml_ptr) < buffer_len) {
            xml_done = 1;
            buffer_len = strlen(xml_ptr);
        }

        memcpy(xml_buffer, xml_ptr, buffer_len);

        if (XML_Parse(parser, xml_buffer, buffer_len, xml_done) == XML_STATUS_ERROR) {
            fprintf(
                stderr,
                "ERROR: %s at line %lu\n",
                XML_ErrorString(XML_GetErrorCode(parser)),
                XML_GetCurrentLineNumber(parser)
            );
            break;
        } else if (xml_done) {
            break;
        }

        xml_ptr = xml_ptr + buffer_len;
    }

    XML_ParserFree(parser);

    return_map = element_data->element_dictionary;

    free_current_element_data(element_data->current_element_data);
    free(element_data->element_path);
    free(element_data);

    return return_map;
}
