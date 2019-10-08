#include "tests/threads/tests.h"
#include <debug.h>
#include <string.h>
#include <stdio.h>

struct test 
  {
    const char *name;
    test_func *function;
  };

static struct test tests[] = 
  {
    {"alarm-single", test_alarm_single},
    {"alarm-multiple", test_alarm_multiple},
    {"alarm-simultaneous", test_alarm_simultaneous},
    {"alarm-priority", test_alarm_priority},
    {"alarm-zero", test_alarm_zero},
    {"alarm-negative", test_alarm_negative},
    {"priority-change", test_priority_change},
    {"priority-donate-one", test_priority_donate_one},
    {"priority-donate-multiple", test_priority_donate_multiple},
    {"priority-donate-multiple2", test_priority_donate_multiple2},
    {"priority-donate-nest", test_priority_donate_nest},
    {"priority-donate-sema", test_priority_donate_sema},
    {"priority-donate-lower", test_priority_donate_lower},
    {"priority-donate-chain", test_priority_donate_chain},
    {"priority-fifo", test_priority_fifo},
    {"priority-preempt", test_priority_preempt},
    {"priority-sema", test_priority_sema},
    {"priority-condvar", test_priority_condvar},
    {"mlfqs-load-1", test_mlfqs_load_1},
    {"mlfqs-load-60", test_mlfqs_load_60},
    {"mlfqs-load-avg", test_mlfqs_load_avg},
    {"mlfqs-recent-1", test_mlfqs_recent_1},
    {"mlfqs-fair-2", test_mlfqs_fair_2},
    {"mlfqs-fair-20", test_mlfqs_fair_20},
    {"mlfqs-nice-2", test_mlfqs_nice_2},
    {"mlfqs-nice-10", test_mlfqs_nice_10},
    {"mlfqs-block", test_mlfqs_block},
  };

static const char *test_name;

/* Runs the test named NAME. */
void
run_test (const char *name) 
{
  const struct test *t;

  // BEGIN - added at UTCN (2018)
  //  due to not initializing (maybe linking problems) correctly "static const" structures (see above "static const struct test tests[]")
  //  we changed them in non-constants and initialized explicitely

  tests[0].name = "alarm-single";
  tests[0].function = test_alarm_single;

  tests[1].name = "alarm-multiple";
  tests[1].function = test_alarm_multiple;

  tests[2].name = "alarm-simultaneous";
  tests[2].function = test_alarm_simultaneous;

  tests[3].name = "alarm-priority";
  tests[3].function = test_alarm_priority;

  tests[4].name = "alarm-zero";
  tests[4].function = test_alarm_zero;

  tests[5].name = "alarm-negative";
  tests[5].function = test_alarm_negative;

  tests[6].name = "priority-change";
  tests[6].function = test_priority_change;

  tests[7].name = "priority-donate-one";
  tests[7].function = test_priority_donate_one;

  tests[8].name = "priority-donate-multiple";
  tests[8].function = test_priority_donate_multiple;

  tests[9].name = "priority-donate-multiple2";
  tests[9].function = test_priority_donate_multiple2;

  tests[10].name = "priority-donate-nest";
  tests[10].function = test_priority_donate_nest;

  tests[11].name = "priority-donate-sema";
  tests[11].function = test_priority_donate_sema;

  tests[12].name = "priority-donate-lower";
  tests[12].function = test_priority_donate_lower;

  tests[13].name = "priority-donate-chain";
  tests[13].function = test_priority_donate_chain;

  tests[14].name = "priority-fifo";
  tests[14].function = test_priority_fifo;

  tests[15].name = "priority-preempt";
  tests[15].function = test_priority_preempt;

  tests[16].name = "priority-sema";
  tests[16].function = test_priority_sema;

  tests[17].name = "priority-condvar";
  tests[17].function = test_priority_condvar;

  tests[18].name = "mlfqs-load-1";
  tests[18].function = test_mlfqs_load_1;

  tests[19].name = "mlfqs-load-60";
  tests[19].function = test_mlfqs_load_60;

  tests[20].name = "mlfqs-load-avg";
  tests[20].function = test_mlfqs_load_avg;

  tests[21].name = "mlfqs-recent-1";
  tests[21].function = test_mlfqs_recent_1;

  tests[22].name = "mlfqs-fair-2";
  tests[22].function = test_mlfqs_fair_2;

  tests[23].name = "mlfqs-fair-20";
  tests[23].function = test_mlfqs_fair_20;

  tests[24].name = "mlfqs-nice-2";
  tests[24].function = test_mlfqs_nice_2;

  tests[25].name = "mlfqs-nice-10";
  tests[25].function = test_mlfqs_nice_10;

  tests[26].name = "mlfqs-block";
  tests[26].function = test_mlfqs_block;

  // END - added at UTCN (2018)

  for (t = tests; t < tests + sizeof tests / sizeof *tests; t++)
    if (!strcmp (name, t->name))
      {
        test_name = name;
        msg ("begin");
        t->function ();
        msg ("end");
        return;
      }
  PANIC ("no test named \"%s\"", name);
}

/* Prints FORMAT as if with printf(),
   prefixing the output by the name of the test
   and following it with a new-line character. */
void
msg (const char *format, ...) 
{
  va_list args;
  
  printf ("(%s) ", test_name);
  va_start (args, format);
  vprintf (format, args);
  va_end (args);
  putchar ('\n');
}

/* Prints failure message FORMAT as if with printf(),
   prefixing the output by the name of the test and FAIL:
   and following it with a new-line character,
   and then panics the kernel. */
void
fail (const char *format, ...) 
{
  va_list args;
  
  printf ("(%s) FAIL: ", test_name);
  va_start (args, format);
  vprintf (format, args);
  va_end (args);
  putchar ('\n');

  PANIC ("test failed");
}

/* Prints a message indicating the current test passed. */
void
pass (void) 
{
  printf ("(%s) PASS\n", test_name);
}

