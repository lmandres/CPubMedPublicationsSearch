#include <stdio.h>
#include <stdlib.h>

#include <curl/curl.h>

#include "xml_helper.h"


static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void **userp) {

    char *ptr;
    char *rptr = (char *)*userp;

    unsigned int userplen = 0;

    userplen = strlen(rptr);

    ptr = (char *)malloc((size*nmemb)+1);
    memset(ptr, '\0', (size*nmemb)+1);
    memcpy(ptr, contents, size*nmemb);

    rptr = (char *)realloc(rptr, (userplen*sizeof(char))+(size*nmemb)+1);
    memcpy(&(rptr[userplen]), ptr, (size*nmemb)+1);

    *userp = rptr;
    free(ptr);

    return size*nmemb;
}

int main(int argc, char *argv[]) {

    char *efetchURL = "https://eutils.ncbi.nlm.nih.gov/entrez/eutils/efetch.fcgi";
    char *efetchPostData = "retmode=xml&db=pubmed&email=lmandres%40yahoo.com&tool=PubMed-Publications-Search&api_key=6da05439891144f16a399d871be54dead708&id=31454628";

    CURL *curl;
    CURLcode res;
    char *read_buffer;

    read_buffer = (char *)malloc(1);
    memset(read_buffer, '\0', 1);

    curl = curl_easy_init();
    if (curl) {

        Map *element_dict;
        Map *test_map;
        List *cdata_list;

        curl_easy_setopt(curl, CURLOPT_URL, efetchURL);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, efetchPostData);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&read_buffer);

        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        element_dict = get_xml_map(read_buffer);

        test_map = get_element_map(
            element_dict,
            "<PubmedArticleSet><PubmedArticle><MedlineCitation><PMID>"
        );
        cdata_list = map_get(test_map, "character_data");
        printf("PubMed ID: %s\n", (char *)list_get(cdata_list, 0));

        test_map = get_element_map(
            element_dict,
            "<PubmedArticleSet><PubmedArticle><MedlineCitation><Article><Journal><Title>"
        );
        cdata_list = map_get(test_map, "character_data");
        printf("Journal Title: %s\n", (char *)list_get(cdata_list, 0));

        test_map = get_element_map(
            element_dict,
            "<PubmedArticleSet><PubmedArticle><MedlineCitation><Article><ArticleTitle>"
        );
        cdata_list = map_get(test_map, "character_data");
        printf("Article Title: %s\n", (char *)list_get(cdata_list, 0));

        if (argc >= 2) {
            test_map = get_element_map(
                element_dict,
                argv[1]
            );
            if (test_map != NULL) {
                cdata_list = map_get(test_map, "character_data");
                printf("%s\n%s\n", argv[1], (char *)list_get(cdata_list, 0));
            } else {
                printf("Nothing found for following path:\n%s\n", argv[1]);
            }
        }

        free_element_dict(element_dict);
        free(read_buffer);
    }

    return 0;
}
                                                       
