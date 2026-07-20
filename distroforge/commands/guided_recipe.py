from __future__ import annotations

import argparse
import json

from distroforge.core.recipe_ai import RecipeAdvisor


def run_guided_recipe(args: argparse.Namespace) -> None:
    from distroforge.ai.review import ConstrainedRecipeAssistant
    from distroforge.core.education import (
        get_guided_recipe,
        guided_recipes_json,
        render_guided_recipes,
    )

    if not args.name:
        print(guided_recipes_json() if args.json else render_guided_recipes())
        return
    recipe = get_guided_recipe(args.name)
    data = ConstrainedRecipeAssistant().suggest_definition(recipe.prompt)
    print(json.dumps(data, indent=2) if args.json else RecipeAdvisor().render_json(recipe.prompt))
    return
