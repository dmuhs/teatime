The Architecture of Teatime
===========================

In this document we will get to know the design decisions behind Teatime and
introduce the library's primitives to make development more intuitive. There
are five components to Teatime that make up its inner workings:

- **Scanner**: A scanner executes one or more plugins on a given target
- **Plugin**: Plugins are where the magic happens: They perform the checks and generate issues
- **Context**: The context object is passed from one scanner to the next and holds report meta data
- **Report**: The report object inside the context is where Plugins add their issues
- **Issue**: This basic building block holds data about findings such as title, severity, and much more


Scanner
-------

The :code:`Scanner` class is a user's entry point to Teatime. It takes an IP, port, node type, and
a list of :code:`Plugin` instances to execute on the target. Behind the scenes, it
initializes a fresh :code:`Context` class, which is passed between the plugins to aggregate
report data.

In the current implementation, the :code:`Scanner` class executes the given plugin list
sequentially on the target. The list order is equivalent to the execution order. This means
that a plugin could provide meta data in a report that another plugin further down the line
can use. While this is not recommended because it introduces implicit dependencies, it
can certainly be used to build highly customized and complex scanning pipelines.

After the scan is done, the :code:`Scanner` class attaches the time elapsed for the
scan to the report's meta data.


Plugin
------

The :code:`Plugin` class is a base for all concrete scans of Teatime. A Plugin can
execute one or more checks on the given target. To specify your own behaviour, the
base :code:`Plugin` class contains an abstract method :code:`_check` that can be
overridden by the user. This method gets a :code:`Context` object (hopefully)
containing all relevant meta data needed by the plugin.

For RPC interaction specifically, the :code:`Plugin` class contains a helper
method to query RPC endpoints in a robust way and handle connection errors along the
way. To prevent Teatime from crashing completely in case of plugin-related errors,
it is recommended to raise and reraise a :code:`PluginException`. This can be
caught easily on the top level, e.g. by the routine executing the scanner.


Context
-------

The :code:`Context` object contains report- and target-related information instructing
the :code:`Plugin` classes. It contains the target, the :code:`Report` object, node type,
and an extra data dictionary for any additional information that e.g. needs to be passed
further down the plugin pipeline. Per scan, there is only one :code:`Context` instance
(initialized in the :code:`Scanner` at the beginning of a scan), which gets shared
across Plugin instances as they are executed in the pipeline.


Report
------

The :code:`Report` object is essentially a container for :code:`Issue` objects, along
with meta data on the executed scan. It contains a UUID for traceability, the target,
a creation timestamp, a list of issues, and a meta data dictionary for any additional
information that should be communicated to the user.

The idea of wrapping issues in a report and duplicating information such as the target
is that each :code:`Report` object should be independent. Thinking of developers who
might want to pass Teatime report data into a database, or export it as a file, this
is a nice property to have, because no additional data apart from the object itself is
required.

Furthermore, the :code:`Report` class contains various helper methods that make
serialization and common checks, such as checking for high-severity issues, easier.


Issue
-----

This is the lowest-level primitive. The :code:`Issue` object can be added to a
:code:`Report` instance by using its :code:`add_issue` method. Each issue contains
a UUID for traceability, a title, description, severity, and a raw data field. The
latter one is meant to contain the raw RPC response. For example, if a scan has
detected an information leak, the raw data field can be populated with the actual
leaking information text, without cluttering the title or description - thus keeping
issues readable and allowing the user to omit large strings when presenting an issue
to the user.

Just like the :code:`Report` class, an :code:`Issue` object contains various helper
method for easier serialization, as well as determining whether the issue at hand is
severe. Wrapping issues into their own object has the advantage of enforcing a standard
format across plugins and requiring them to provide information that help the user
make sense of what has been reported.
