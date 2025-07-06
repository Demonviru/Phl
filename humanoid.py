import bpy
from mathutils import Vector
import math

# --- Utility functions ---
def create_sphere(name, radius, location):
    bpy.ops.mesh.primitive_uv_sphere_add(radius=radius, location=location)
    obj = bpy.context.active_object
    obj.name = name
    return obj

def create_cylinder(name, radius, depth, location, rotation=(0,0,0)):
    bpy.ops.mesh.primitive_cylinder_add(radius=radius, depth=depth, location=location, rotation=rotation)
    obj = bpy.context.active_object
    obj.name = name
    return obj

def create_cube(name, size, location):
    bpy.ops.mesh.primitive_cube_add(size=size, location=location)
    obj = bpy.context.active_object
    obj.name = name
    return obj

def add_material(obj, name, color):
    mat = bpy.data.materials.new(name=name)
    mat.diffuse_color = (*color, 1)
    obj.data.materials.append(mat)

def add_armature(name, bones_data):
    bpy.ops.object.armature_add(enter_editmode=True)
    arm = bpy.context.object
    arm.name = name
    arm.show_in_front = True
    amt = arm.data
    amt.edit_bones.remove(amt.edit_bones[0])  # remove default bone

    # Add bones
    for bone_name, head, tail in bones_data:
        bone = amt.edit_bones.new(bone_name)
        bone.head = Vector(head)
        bone.tail = Vector(tail)

    bpy.ops.object.mode_set(mode='OBJECT')
    return arm

# --- Build dummy parts ---
bpy.ops.object.select_all(action='SELECT')
bpy.ops.object.delete()  # clear scene

# Head
head = create_sphere('Head', 0.21, (0, 0, 1.68))
add_material(head, 'HeadMat', (0.05, 0.4, 0.85))  # blue

# Torso (upper chest)
chest = create_cylinder('Chest', 0.28, 0.46, (0, 0, 1.25))
add_material(chest, 'ChestMat', (0.05, 0.4, 0.85))

# Abdomen
abdomen = create_cylinder('Abdomen', 0.22, 0.28, (0, 0, 0.95))
add_material(abdomen, 'AbdomenMat', (0.85, 0.1, 0.1))  # red

# Pelvis
pelvis = create_cylinder('Pelvis', 0.23, 0.26, (0, 0, 0.7))
pelvis.rotation_euler[0] = math.radians(90)
add_material(pelvis, 'PelvisMat', (0.85, 0.1, 0.1))

# Upper arms
upper_arm_L = create_cylinder('UpperArm_L', 0.08, 0.35, (-0.34, 0, 1.42), (0, 0, math.radians(10)))
upper_arm_R = create_cylinder('UpperArm_R', 0.08, 0.35, (0.34, 0, 1.42), (0, 0, -math.radians(10)))
add_material(upper_arm_L, 'ArmMat', (0.05, 0.4, 0.85))
add_material(upper_arm_R, 'ArmMat', (0.05, 0.4, 0.85))

# Forearms
forearm_L = create_cylinder('Forearm_L', 0.07, 0.32, (-0.34, 0, 1.10), (0, 0, math.radians(10)))
forearm_R = create_cylinder('Forearm_R', 0.07, 0.32, (0.34, 0, 1.10), (0, 0, -math.radians(10)))
add_material(forearm_L, 'ForearmMat', (0.05, 0.4, 0.85))
add_material(forearm_R, 'ForearmMat', (0.05, 0.4, 0.85))

# Hands
hand_L = create_sphere('Hand_L', 0.09, (-0.34, 0, 0.92))
hand_R = create_sphere('Hand_R', 0.09, (0.34, 0, 0.92))
add_material(hand_L, 'HandMat', (0.85, 0.1, 0.1))
add_material(hand_R, 'HandMat', (0.85, 0.1, 0.1))

# Thighs
thigh_L = create_cylinder('Thigh_L', 0.11, 0.5, (-0.14, 0, 0.43), (0, 0, math.radians(5)))
thigh_R = create_cylinder('Thigh_R', 0.11, 0.5, (0.14, 0, 0.43), (0, 0, -math.radians(5)))
add_material(thigh_L, 'ThighMat', (0.05, 0.4, 0.85))
add_material(thigh_R, 'ThighMat', (0.05, 0.4, 0.85))

# Calves
calf_L = create_cylinder('Calf_L', 0.09, 0.45, (-0.14, 0, 0.14), (0, 0, math.radians(5)))
calf_R = create_cylinder('Calf_R', 0.09, 0.45, (0.14, 0, 0.14), (0, 0, -math.radians(5)))
add_material(calf_L, 'CalfMat', (0.05, 0.4, 0.85))
add_material(calf_R, 'CalfMat', (0.05, 0.4, 0.85))

# Feet
foot_L = create_cube('Foot_L', 0.18, (-0.14, 0.09, -0.13))
foot_L.scale[1] = 2
foot_R = create_cube('Foot_R', 0.18, (0.14, 0.09, -0.13))
foot_R.scale[1] = 2
add_material(foot_L, 'FootMat', (0.85, 0.1, 0.1))
add_material(foot_R, 'FootMat', (0.85, 0.1, 0.1))

# --- Armature (rigging) ---
bones = [
    ("Spine", (0,0,0.7), (0,0,1.45)),
    ("Head", (0,0,1.45), (0,0,1.68)),
    ("UpperArm_L", (0,0,1.45), (-0.34,0,1.42)),
    ("Forearm_L", (-0.34,0,1.42), (-0.34,0,1.10)),
    ("Hand_L", (-0.34,0,1.10), (-0.34,0,0.92)),
    ("UpperArm_R", (0,0,1.45), (0.34,0,1.42)),
    ("Forearm_R", (0.34,0,1.42), (0.34,0,1.10)),
    ("Hand_R", (0.34,0,1.10), (0.34,0,0.92)),
    ("Thigh_L", (0,0,0.7), (-0.14,0,0.43)),
    ("Calf_L", (-0.14,0,0.43), (-0.14,0,0.14)),
    ("Foot_L", (-0.14,0,0.14), (-0.14,0.09,-0.13)),
    ("Thigh_R", (0,0,0.7), (0.14,0,0.43)),
    ("Calf_R", (0.14,0,0.43), (0.14,0,0.14)),
    ("Foot_R", (0.14,0,0.14), (0.14,0.09,-0.13)),
]

armature = add_armature('CrashTestArmature', bones)

# --- Parenting objects to armature (using automatic weights or parent to bone) ---
objs = [head, chest, abdomen, pelvis, upper_arm_L, upper_arm_R, forearm_L, forearm_R, hand_L, hand_R, thigh_L, thigh_R, calf_L, calf_R, foot_L, foot_R]
for obj in objs:
    obj.select_set(True)
armature.select_set(True)
bpy.context.view_layer.objects.active = armature
bpy.ops.object.parent_set(type='ARMATURE_AUTO')

# --- Decorative crash test markings (stickers) ---
def add_crash_test_marking(obj, location, scale):
    bpy.ops.mesh.primitive_circle_add(vertices=32, radius=scale, location=location)
    circle = bpy.context.active_object
    circle.parent = obj
    add_material(circle, "MarkingMat", (1, 1, 0))  # yellow
    # You can replace this with an image texture for a real crash test logo

# Example stickers on head and arm
add_crash_test_marking(head, (0, 0.18, 1.68), 0.06)
add_crash_test_marking(upper_arm_L, (-0.34, 0.08, 1.42), 0.05)
add_crash_test_marking(chest, (0, 0.28, 1.25), 0.08)

# --- Notes ---
# - This script generates a rigged, segmented crash-test dummy droid with color segmentation and crash-test stickers,
#   following the reference images for color/shape and rig complexity.
# - For a more detailed model, you can further sculpt or subdivide the meshes.
# - For realistic crash test logos, replace circles with image textures.
# - Run this script in Blender's scripting workspace.
