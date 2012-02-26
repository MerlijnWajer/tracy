Introduction to Soxy
====================




.. http://sphinx.pocoo.org/domains.html#the-c-domain

Tracy
-----

.. c:function:: int fork_trace_exec(int argc, char **argv);
.. c:function:: int wait_for_syscall(struct soxy_ll *l, struct soxy_event *s);
.. c:function:: int continue_syscall(struct soxy_event *s);
.. c:function:: int check_syscall(struct soxy_ll *l, struct soxy_event *s);
.. c:function:: char* get_syscall_name(int syscall);

.. c:function:: int hook_into_syscall(struct soxy_ll *l, char *syscall, int pre, syscall_hook_func func);
.. c:function:: int execute_hook(struct soxy_ll *ll, char *syscall, struct soxy_event *e);

.. c:function:: int read_word(struct soxy_event *e, long from, long* word);
.. c:function:: int read_data(struct soxy_event *e, long from, void *to, long size);

.. c:function:: int write_word(struct soxy_event *e, long to, long word);
.. c:function:: int write_data(struct soxy_event *e, long to, void *from, long size);

.. c:function:: int modify_registers(struct soxy_event *e);
