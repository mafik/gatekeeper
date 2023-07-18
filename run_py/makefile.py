'''Contains the graph of recipes to build ::maf.'''

import googletest
import cc
import make

recipe = make.Recipe()
googletest.AddSteps(recipe)
cc.AddSteps(recipe)
