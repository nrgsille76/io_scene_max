# SPDX-FileCopyrightText: 2023-2024 Sebastian Schrand
#
# SPDX-License-Identifier: GPL-2.0-or-later

import bpy
from bpy_extras.io_utils import (
    ImportHelper,
    orientation_helper,
    axis_conversion,
    poll_file_object_drop,
)
from bpy.props import (
    BoolProperty,
    FloatProperty,
    StringProperty,
    CollectionProperty,
)

if "bpy" in locals():
    import importlib
    if "import_max" in locals():
        importlib.reload(import_max)


@orientation_helper(axis_forward='Y', axis_up='Z')
class ImportMax(bpy.types.Operator, ImportHelper):
    """Import Autodesk MAX"""
    bl_idname = "import_scene.max"
    bl_label = "Import MAX (.max)"
    bl_options = {'PRESET', 'UNDO'}

    filename_ext = ".max"
    filter_glob: StringProperty(default="*.max", options={'HIDDEN'})
    files: CollectionProperty(type=bpy.types.OperatorFileListElement, options={'HIDDEN', 'SKIP_SAVE'})
    directory: StringProperty(subtype='DIR_PATH')

    scale_objects: FloatProperty(
        name="Scale",
        description="Scale factor for all objects",
        min=0.0, max=10000.0,
        soft_min=0.0, soft_max=10000.0,
        default=1.0,
    )
    use_material: BoolProperty(
        name="Materials",
        description="Import the materials of the objects",
        default=True,
    )
    use_uv_mesh: BoolProperty(
        name="UV Mesh",
        description="Import texture coordinates as mesh objects",
        default=False,
    )
    use_collection: BoolProperty(
        name="Collection",
        description="Create a new collection",
        default=False,
    )
    use_apply_matrix: BoolProperty(
        name="Apply Matrix",
        description="Use matrix to transform the objects",
        default=False,
    )

    def draw(self, context):
        layout = self.layout
        layout.use_property_split = True
        layout.use_property_decorate = False

        import_include(layout, self)
        import_transform(layout, self)

    def execute(self, context):
        from . import import_max
        keywords = self.as_keywords(ignore=("axis_forward", "axis_up", "filter_glob"))
        global_matrix = axis_conversion(from_forward=self.axis_forward, from_up=self.axis_up,).to_4x4()
        keywords["global_matrix"] = global_matrix

        return import_max.load(self, context, **keywords)

    def invoke(self, context, event):
        return self.invoke_popup(context)


def import_include(layout, operator):
    header, body = layout.panel("MAX_import_include", default_closed=False)
    header.label(text="Include")
    if body:
        layrow = layout.row(align=True)
        layrow.prop(operator, "use_material")
        layrow.label(text="", icon='MATERIAL' if operator.use_material else 'SHADING_TEXTURE')
        layrow = layout.row(align=True)
        layrow.prop(operator, "use_uv_mesh")
        layrow.label(text="", icon='UV' if operator.use_uv_mesh else 'GROUP_UVS')
        layrow = layout.row(align=True)
        layrow.prop(operator, "use_collection")
        layrow.label(text="", icon='OUTLINER_COLLECTION' if operator.use_collection else 'GROUP')


def import_transform(layout, operator):
    header, body = layout.panel("MAX_import_transform", default_closed=False)
    header.label(text="Transform")
    if body:
        layout.prop(operator, "scale_objects")
        layrow = layout.row(align=True)
        layrow.prop(operator, "use_apply_matrix")
        layrow.label(text="", icon='VIEW_ORTHO' if operator.use_apply_matrix else 'MESH_GRID')
        layout.prop(operator, "axis_forward")
        layout.prop(operator, "axis_up")


class IO_FH_max(bpy.types.FileHandler):
    bl_idname = "IO_FH_max"
    bl_label = "3DS MAX"
    bl_import_operator = "import_scene.max"
    bl_export_operator = "export_scene.max"
    bl_file_extensions = ".max"

    @classmethod
    def poll_drop(cls, context):
        return poll_file_object_drop(context)


def menu_func(self, context):
    self.layout.operator(ImportMax.bl_idname, text="Autodesk MAX (.max)")


def register():
    bpy.utils.register_class(ImportMax)
    bpy.utils.register_class(IO_FH_max)
    bpy.types.TOPBAR_MT_file_import.append(menu_func)


def unregister():
    bpy.types.TOPBAR_MT_file_import.remove(menu_func)
    bpy.utils.unregister_class(IO_FH_max)
    bpy.utils.unregister_class(ImportMax)


if __name__ == "__main__":
    register()
