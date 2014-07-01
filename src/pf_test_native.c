#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <time.h>

typedef unsigned int uint_t;
typedef int bool_t;

#define TRUE  0
#define FALSE 1

#define DBG_DUMP_S(s) ({ \
      printf("%s\n", s.filter); \
      printf("%s\n", s.pcap_file); \
      printf("%d\n", s.exp_result); \
      printf("%d\n", s.stat.pkt_seen); \
      printf("%f\n", s.stat.et); \
})

typedef struct {
   uint_t pkt_seen;
   float  et;
} stat_t;

struct {
   char   *filter;
   char   *pcap_file;
   uint_t exp_result;
   stat_t stat;
} s;

bool_t print_error_and_die(char *s) {
   fprintf(stderr, "%s", s);
   exit(-1);
}

char *clone_str_or_die(char *s) {
   char *t = strdup(s);
   if (t==NULL)
      print_error_and_die("clone_str_or_die failed\n");
   return t;
}

void load_args_or_die(int argc, char **argv) {
   char *aux;

   /* format: filter pcap_file exp_result */
   if (argc != 4)
      print_error_and_die("Invalid syntax. Use ./pf_test_native filter pcap_file exp_result\n");

   /* load args */
   s.filter     = clone_str_or_die(argv[1]);
   s.pcap_file  = clone_str_or_die(argv[2]);
   aux          = clone_str_or_die(argv[3]);
   s.exp_result = strtol(aux, (char **)NULL, 10);
}

void run_filter_on_pcap_or_die(char *filter, char *pcap_file) {
   char errbuf[PCAP_ERRBUF_SIZE];
   struct pcap_pkthdr header;
   struct bpf_program fp;
   pcap_t *handle;
   unsigned int pkt_counter;
   float start, end;

   handle = pcap_open_offline(pcap_file, errbuf);
   if (handle == NULL)
      print_error_and_die("pcap_open_offline failed\n");

   if (pcap_compile(handle, &fp, filter, 0, -1) == -1)
      print_error_and_die("pcap_compile failed\n");

   if (pcap_setfilter(handle, &fp) == -1)
      print_error_and_die("pcap_setfilter failed\n");

   pkt_counter = 0;

   start = (float)clock()/CLOCKS_PER_SEC;

   while (pcap_next(handle, &header))
      pkt_counter++;

   end = (float)clock()/CLOCKS_PER_SEC;

   s.stat.et = end - start;
   s.stat.pkt_seen = pkt_counter;
}

void show_result_and_stats() {
   printf("pkt_seen:%d, elapsed_time: %f, pass: %s\n", s.stat.pkt_seen,
               s.stat.et, s.stat.pkt_seen == s.exp_result ? "TRUE" : "FALSE");
}

int main(int argc, char **argv) {

   /* check and load args */
   load_args_or_die(argc, argv);

   /* run filter and gather stats */
   run_filter_on_pcap_or_die(s.filter, s.pcap_file);

   /* show result and stats */
   show_result_and_stats();

   return 0;
}
