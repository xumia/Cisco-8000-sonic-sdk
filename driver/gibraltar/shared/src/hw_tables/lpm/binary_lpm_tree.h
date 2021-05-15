// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#ifndef __LEABA_BINARY_LPM_TREE_H_
#define __LEABA_BINARY_LPM_TREE_H_

#include "common/common_strings.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "lpm_common.h"

#include <memory>
#include <sstream>

namespace silicon_one
{

template <class data_t>
class tree_node;

/// @brief LPM tree generalization.
///
/// A generic templated binary tree holding LPM keys and their associated data.
///
/// An LPM tree handles insertion, finding and removal of prefixes.
template <class data_t>
class binary_lpm_tree
{
public:
    /// These constants represent whether child of node is left or right.
    static constexpr const bool LEFT_CHILD = false;
    static constexpr const bool RIGHT_CHILD = true;

    using tree_node_t = tree_node<data_t>;
    using tree_node_sptr = std::shared_ptr<tree_node_t>;
    using tree_node_scptr = std::shared_ptr<const tree_node_t>;
    using tree_node_wptr = weak_ptr_unsafe<tree_node_t>;

    /// @brief Construct an empty binary tree.
    binary_lpm_tree();

    /// @brief Construct an empty binary tree.
    ///
    /// @param[in] name     Name of tree stored as std::string.
    explicit binary_lpm_tree(const std::string& name);

    /// @brief Returns path from last clearing of path to node determined by following rule:
    /// If node with supplied key doesn't exist, path returned is to the longest prefix match node, unless LPM node has a child in
    /// direction of prefix and forwarded function returns false for the child node. In that case the last node in returned vector
    /// is the child node. Every node in path is checked with passed function, and if the function returns true, path is cleared
    /// and built from this node onwards, including that node.
    ///
    /// @param[in] key                           Prefix of node to search for.
    /// @param[in] clearing_vector_point_func    Function poiter which tells whether to clear path.
    ///
    /// @return  Desired path.
    vector_alloc<tree_node_t*> get_path(const lpm_key_t& key, bool (*clearing_vector_point_func)(const tree_node_t*)) const;

    /// @brief Returns a node with given key if it exists in tree, else it returns LPM node or child of LPM node in the direction of
    /// key.
    ///
    /// In case node with provided key doesn't exist in tree, this is the rules by which node is selected:
    /// return longest prefix match node if it doesn't have children
    /// else if LPM node has child in direction where searched node should be, return that child of LPM node instead.
    ///
    /// @param[in] key     Prefix of node to be searched for.
    ///
    /// @return Corresponding node.
    tree_node_t* find_node(const lpm_key_t& key) const;

    /// @brief Returns a node with given key if it exists in tree, else it returns LPM node or child of LPM node in the direction of
    /// key.
    ///
    /// In case node with provided key doesn't exist in tree, this is the rules by which node is selected:
    /// return longest prefix match node if it doesn't have children
    /// else if LPM node has child in direction where searched node should be, return that child of LPM node instead.
    ///
    /// @param[in] key            Prefix of node to be searched for.
    /// @param[in] start_node     Begin searching tree from this node.
    ///
    /// @return  Corresponding node.
    tree_node_t* find_node(const lpm_key_t& key, const tree_node_t* start_node) const;

    /// @brief Perform a longest prefix match of a key by walking the tree. Only valid nodes are returned or root node(which can be
    /// invalid).
    ///
    /// @param[in] key                   Key used for searching.
    ///
    /// @return  Node which is longest prefix match of the key.
    tree_node_t* longest_prefix_match_lookup(const lpm_key_t& key) const;

    /// @brief Insert given node to tree near node given. This is optimization variation.
    ///
    /// @param[in] reference_node     Obtained from find_node() method.
    /// @param[in] key                Prefix of new node to be inserted.
    /// @param[in] data               Initialize data attribute of node.
    ///
    /// @return  Pointer to newly inserted node. Null pointer if node already exists and is valid.
    tree_node_t* insert_node_to_tree(tree_node_t* reference_node, const lpm_key_t& key, const data_t& data);

    /// @brief Insert given node to tree.
    ///
    /// @param[in]      key                Prefix of new node to be inserted.
    /// @param[out]     out_node           Pointer to newly inserted node. Null pointer if node already exists and is valid.
    ///
    /// @return  #la_status.
    la_status insert_node_to_tree(const lpm_key_t& key, tree_node_t*& out_node);

    /// @brief Remove node from tree.
    ///
    /// @param[in] node     Node which will be removed.
    void remove_node_from_tree(tree_node_t* node);

    /// @brief Remove node from tree.
    ///
    /// @param[in] key     Prefix of node that will be removed from tree.
    ///
    /// @return #la_status.
    la_status remove_node_from_tree(const lpm_key_t& key);

    /// @brief Return root node of the tree.
    ///
    /// @return  Root node of tree.
    const tree_node_t* get_root() const;

    /// @brief Return name of the tree
    ///
    /// @return  Name of tree.
    const std::string& get_name() const;

    /// @brief Calls all of sanity check methods for tree.
    ///
    /// @return  True if all checks pass.
    bool sanity() const;

    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(m_root, m_name);
    }

private:
    /// @brief Inserts new node on edge connecting current node with its parent, adding invalid node if needed.
    ///
    /// @param[in] current_node     Node on which edge new node is being created.
    /// @param[in] node             Node to be inserted to tree.
    ///
    /// @return  node.
    tree_node_t* insert_node_between_two_nodes(tree_node_t* current_node, tree_node_t* node);

    /// @brief Check that the tree doesn't have pointers loop which indicates on data corruption.
    ///
    /// @param[in] node          Node to start sanity check.
    ///
    /// @return True if there are no loops.
    bool sanity_check_loop_free(const tree_node_t* node) const;

    /// @brief Check that the tree doesn't have pointers loop which indicates on data corruption.
    ///
    /// @param[in]     node          Node to start sanity check.
    /// @param[in,out] visited       Set of already visited nodes.
    ///
    /// @return True if there are no loops.
    bool sanity_check_loop_free(const tree_node_t* node, set_alloc<const tree_node_t*>& visited) const;

    /// @brief Check that all parent<->child pointers are correct and that every invalid node has 2 children.
    ///
    /// @param[in] node          Node to start sanity check.
    ///
    /// @return True if all parent<->children connections are legal.
    bool sanity_check_child_parent(const tree_node_t* node) const;

    /// Data members
    tree_node_sptr m_root; ///< Tree root node.
    std::string m_name;    ///< Optional name of tree(used in debugging log).
};

/// @brief Template for nodes of binary tree.
///
/// Describes a single tree node, a building block of a binary tree, which contains key.
template <class data_t>
class tree_node : public std::enable_shared_from_this<tree_node<data_t> >
{
public:
    // Aliases used in definition of class.
    using tree_node_t = tree_node;
    using tree_node_sptr = std::shared_ptr<tree_node>;
    using tree_node_scptr = std::shared_ptr<const tree_node_t>;
    using tree_node_wptr = weak_ptr_unsafe<tree_node>;
    using tree_node_wcptr = weak_ptr_unsafe<const tree_node_t>;

    template <class tree_node>
    friend class binary_lpm_tree;

    /// @brief Copy constructor deleted.
    tree_node(const tree_node&) = delete;

    /// @brief Construct a tree node with given key.
    ///
    /// Construct new empty node without key, children or parent.
    tree_node();

    /// @brief Construct a tree node with given key and data.
    ///
    /// Construct new node with a given key, without children or parent.
    ///
    /// @param[in]      key             Key to be stored in the node.
    /// @param[in]      is_valid        Validity of node.
    /// @param[in]      data            Additional data for node.
    tree_node(const lpm_key_t& key, bool is_valid, const data_t& data);

    /// @brief String representation of tree_node.
    ///
    /// @return string which describes node.
    std::string to_string() const;

    /// @brief Return width of the node's key.
    ///
    /// @return         width in bits.
    size_t get_width() const;

    /// @brief Check if node is leaf.
    ///
    /// Node is leaf if it has no children.
    ///
    /// @return         True if leaf, false otherwise.
    bool is_leaf() const;

    /// @brief Return upstream entry for the given node.
    ///
    /// @return         upstream entry if exists.
    tree_node* ancestor();
    const tree_node* ancestor() const;

    /// @brief Getter for key.
    ///
    /// @return  Prefix stored in node.
    const lpm_key_t& get_key() const;

    /// @brief Return left child node.
    ///
    /// @return Left child node.
    tree_node* get_left_child();
    const tree_node* get_left_child() const;

    /// @brief Return right child node.
    ///
    /// @return Right child node.
    tree_node* get_right_child();
    const tree_node* get_right_child() const;

    /// @brief Return parent node.
    ///
    /// @return Parent node.
    tree_node* get_parent_node();
    const tree_node* get_parent_node() const;

    /// @brief Return special data.
    ///
    /// @return Pointer to data.
    data_t& data();
    const data_t& data() const;

    /// @brief Set new data in node.
    ///
    /// @param[in] new_data New data to be stored in node.
    void set_data(const data_t& new_data);

    /// @brief Check validity of node.
    ///
    /// @return Validity of node.
    bool is_valid() const;

    template <class Archive>
    void serialize(Archive& ar)
    {
        ar(const_cast<lpm_key_t&>(m_key));
        ar(m_parent_node);
        ar(m_left_child);
        ar(m_right_child);
        ar(m_data);
        ar(m_is_valid_node);
    }

private:
    /// @brief Set a child of current node. Also set current node as a parent of given node.
    ///
    /// @param[in]      node                    Node to set.
    /// @param[in]      is_right                Direction of child: true for right child, false for left child.
    void set_as_child(tree_node* node, bool is_right);

    /// Members
    const lpm_key_t m_key;        ///< Key, can't be changed.
    tree_node_wptr m_parent_node; ///< Parent node (weak pointer).
    tree_node_sptr m_left_child;  ///< Left child node.
    tree_node_sptr m_right_child; ///< Right child node.
    data_t m_data;                ///< Special data that node contains.
    bool m_is_valid_node;         ///< Is node entered or auxiliary.
};

template <class data_t>
binary_lpm_tree<data_t>::binary_lpm_tree() : m_root(std::make_shared<tree_node_t>()), m_name("Binary tree")
{
}

template <class data_t>
binary_lpm_tree<data_t>::binary_lpm_tree(const std::string& name) : m_root(std::make_shared<tree_node_t>()), m_name(name)
{
}

template <class data_t>
vector_alloc<tree_node<data_t>*>
binary_lpm_tree<data_t>::get_path(const lpm_key_t& key, bool (*clearing_vector_point_func)(const tree_node_t*)) const
{
    vector_alloc<tree_node_t*> path_of_tree;
    tree_node_t* current_node = m_root.get();

    while (is_contained(current_node->m_key, key)) {
        bool clear_path = clearing_vector_point_func(current_node);
        if (clear_path) {
            path_of_tree.clear();
        }

        path_of_tree.push_back(current_node);
        size_t current_width = current_node->get_width();
        bool go_right = key.bit_from_msb(current_width);
        tree_node_t* next_node = go_right ? current_node->m_right_child.get() : current_node->m_left_child.get();
        if (!next_node) {
            return path_of_tree;
        }

        current_node = next_node;
    }

    const tree_node_wptr& parent = current_node->m_parent_node;
    if (parent && parent->m_key == key) {
        return path_of_tree;
    }

    if (!clearing_vector_point_func(current_node)) {
        path_of_tree.push_back(current_node);
    }

    return path_of_tree;
}

template <class data_t>
tree_node<data_t>*
binary_lpm_tree<data_t>::find_node(const lpm_key_t& key) const
{
    return find_node(key, m_root.get());
}

template <class data_t>
tree_node<data_t>*
binary_lpm_tree<data_t>::find_node(const lpm_key_t& key, const tree_node_t* start_node) const
{
    const tree_node_t* current_node = start_node;
    while (is_contained(current_node->m_key, key)) {
        size_t current_width = current_node->get_width();
        bool go_right = key.bit_from_msb(current_width);
        const tree_node_t* next_node = go_right ? current_node->m_right_child.get() : current_node->m_left_child.get();
        if (next_node == nullptr) {
            return const_cast<tree_node_t*>(current_node);
        }

        current_node = next_node;
    }

    const tree_node_t* parent = current_node->m_parent_node.get();
    if (parent != nullptr && parent->m_key == key) {
        return const_cast<tree_node_t*>(parent);
    }

    return const_cast<tree_node_t*>(current_node);
}

template <class data_t>
tree_node<data_t>*
binary_lpm_tree<data_t>::insert_node_to_tree(tree_node_t* current_node, const lpm_key_t& key, const data_t& data)
{
    const lpm_key_t& current_key(current_node->m_key);
    if (key == current_key) {
        // a. Node with given key exists: replace existing node with new one.
        if (current_node->m_is_valid_node) {
            return nullptr;
        }

        current_node->m_is_valid_node = true;
        current_node->m_data = data;
        log_spam(TABLES,
                 "%s: Invalid node with key=%s/%zu already exists. Making it valid",
                 m_name.c_str(),
                 current_node->m_key.to_string().c_str(),
                 current_node->get_width());

    } else {
        tree_node_sptr new_node_sptr = std::make_shared<tree_node_t>(key, true /* is_valid */, data);
        tree_node_t* new_node = new_node_sptr.get();
        if (is_contained(current_key, key)) {
            // b. Insertion point is a leaf.
            size_t current_width = current_node->get_width();
            bool right_leaf = new_node->m_key.bit_from_msb(current_width);
            current_node->set_as_child(new_node, right_leaf);
            log_spam(TABLES,
                     "%s action: insert node %s to tree as %s child of %s",
                     m_name.c_str(),
                     new_node->to_string().c_str(),
                     right_leaf ? "right" : "left",
                     current_node->to_string().c_str());
        } else {
            // c. Insertion point is between two nodes.
            insert_node_between_two_nodes(current_node, new_node);
        }

        return new_node;
    }

    return current_node;
}

template <class data_t>
la_status
binary_lpm_tree<data_t>::insert_node_to_tree(const lpm_key_t& key, tree_node_t*& out_node)
{
    tree_node_t* closest_node = find_node(key);
    if (closest_node->m_key == key && closest_node->m_is_valid_node) {
        return LA_STATUS_EEXIST;
    }

    out_node = insert_node_to_tree(closest_node, key, data_t());

    return LA_STATUS_SUCCESS;
}

template <class data_t>
tree_node<data_t>*
binary_lpm_tree<data_t>::longest_prefix_match_lookup(const lpm_key_t& key) const
{
    tree_node_t* current_node = m_root.get();
    tree_node_t* res_node = nullptr;
    while (is_contained(current_node->m_key, key)) {
        if (current_node->is_valid()) {
            res_node = current_node;
        }

        size_t current_width = current_node->get_width();
        bool go_right = key.bit_from_msb(current_width);
        tree_node_t* next_node = go_right ? current_node->m_right_child.get() : current_node->m_left_child.get();
        if (!next_node) {
            return res_node;
        }

        current_node = next_node;
    }

    return res_node;
}

template <class data_t>
tree_node<data_t>*
binary_lpm_tree<data_t>::insert_node_between_two_nodes(tree_node_t* current_node, tree_node_t* new_node)
{
    const lpm_key_t& current_key = current_node->m_key;
    tree_node_sptr new_middle_node;
    bool go_right = false;
    bool is_key_a_prefix_of_current_key = is_contained(new_node->m_key, current_key);

    if (is_key_a_prefix_of_current_key) {
        // a. Current key starts with key bits.
        new_middle_node = new_node->shared_from_this();
        size_t width = new_node->get_width();
        go_right = current_key.bit_from_msb(width);
    } else {
        // b. Not a: insert new node as a leaf child of a new middle node.
        lpm_key_t new_middle_node_key = common_key(current_key, new_node->m_key);
        new_middle_node = std::make_shared<tree_node_t>(new_middle_node_key, false /* is_valid */, data_t());

        size_t middle_width = new_middle_node_key.get_width();
        go_right = current_key.bit_from_msb(middle_width);
        new_middle_node->set_as_child(new_node, !go_right);
    }

    tree_node_t* parent = current_node->m_parent_node.get();
    new_middle_node->set_as_child(current_node, go_right);

    bool right_child = (parent->m_right_child.get() == current_node);
    parent->set_as_child(new_middle_node.get(), right_child);

    if (is_key_a_prefix_of_current_key) {
        log_spam(TABLES,
                 "%s action: insert node %s to tree as %s child of %s and parent of a %s child of %s",
                 m_name.c_str(),
                 new_node->to_string().c_str(),
                 right_child ? "right" : "left",
                 parent->to_string().c_str(),
                 go_right ? "right" : "left",
                 current_node->to_string().c_str());

    } else {
        log_spam(TABLES,
                 "%s action: insert node to tree: %s as %s child of a new middle "
                 "node %s which is %s child of %s, The %s son of the new middle node is %s",
                 m_name.c_str(),
                 new_node->to_string().c_str(),
                 !go_right ? "right" : "left",
                 new_middle_node->to_string().c_str(),
                 right_child ? "right" : "left",
                 parent->to_string().c_str(),
                 go_right ? "right" : "left",
                 current_node->to_string().c_str());
    }

    return new_node;
}

template <class data_t>
void
binary_lpm_tree<data_t>::remove_node_from_tree(tree_node_t* node)
{
    dassert_crit(node != nullptr);
    dassert_crit(node->is_valid());
    // In order to avoid deleting the node and mem corruption, we need to hold the ptr till end of function
    tree_node_sptr node_sptr = node->shared_from_this();

    tree_node_t* right = node->m_right_child.get();
    tree_node_t* left = node->m_left_child.get();

    if ((right && left) || node == m_root.get()) {
        log_spam(TABLES,
                 "LPM Tree action: remove node %s from tree: it has 2 children so will make it invalid.",
                 node->to_string().c_str());
        node->m_is_valid_node = false;
        return;
    }

    // Delete node
    tree_node_t* parent = node->m_parent_node.get();
    tree_node_t* child = right ? right : left;
    bool node_is_right = (parent->m_right_child.get() == node);
    parent->set_as_child(child, node_is_right);

    log_spam(TABLES,
             "LPM Tree action: remove node from tree: it has %s so will point from parent "
             "to %s. node %s  parent %s  child %s",
             right ? "1 right child" : (left ? "1 left child" : "no children"),
             child ? "child" : "null",
             node->to_string().c_str(),
             parent->to_string().c_str(),
             child ? child->to_string().c_str() : "null");

    if (child || parent->m_is_valid_node || parent == m_root.get()) {
        return;
    }

    // Delete also the invalid parent that was needed for node.
    tree_node_t* parent_parent = parent->m_parent_node.get();
    tree_node_t* parent_child = (!node_is_right) ? parent->m_right_child.get() : parent->m_left_child.get();
    bool parent_is_right = (parent_parent->m_right_child.get() == parent);

    log_spam(TABLES,
             "LPM Tree action: remove node from tree: Also removing the invalid (and non-root) parent by pointing from "
             "its parent to its new %s child. parent's parent %s",
             parent_is_right ? "right" : "left",
             parent_parent->to_string().c_str());

    parent_parent->set_as_child(parent_child, parent_is_right);
}

template <class data_t>
la_status
binary_lpm_tree<data_t>::remove_node_from_tree(const lpm_key_t& key)
{
    tree_node_t* node = find_node(key);
    if ((node == nullptr) || (node->m_key != key)) {
        return LA_STATUS_ENOTFOUND;
    }

    remove_node_from_tree(node);
    return LA_STATUS_SUCCESS;
}

template <class data_t>
const tree_node<data_t>*
binary_lpm_tree<data_t>::get_root() const
{
    return m_root.get();
}

template <class data_t>
const std::string&
binary_lpm_tree<data_t>::get_name() const
{
    return m_name;
}

template <class data_t>
bool
binary_lpm_tree<data_t>::sanity() const
{
    bool res = true;
    dassert_slow(res = res && sanity_check_child_parent(m_root.get()));
    dassert_slow(res = res && sanity_check_loop_free(m_root.get()));
    return res;
}

template <class data_t>
bool
binary_lpm_tree<data_t>::sanity_check_loop_free(const tree_node_t* node) const
{
    set_alloc<const tree_node_t*> already_visited;
    bool res = sanity_check_loop_free(node, already_visited);
    return res;
}

template <class data_t>
bool
binary_lpm_tree<data_t>::sanity_check_loop_free(const tree_node_t* node, set_alloc<const tree_node_t*>& visited) const
{
    if (node == nullptr) {
        return true;
    }

    if (visited.count(node) > 0) {
        log_err(TABLES, "node=%s has loop", node->to_string().c_str());
        dassert_crit(false);
        return false;
    }

    visited.insert(node);

    bool ret_left = sanity_check_loop_free(node->m_left_child.get(), visited);
    if (!ret_left) {
        return false;
    }

    bool ret_right = sanity_check_loop_free(node->m_right_child.get(), visited);
    if (!ret_right) {
        return false;
    }

    return true;
}

template <class data_t>
bool
binary_lpm_tree<data_t>::sanity_check_child_parent(const tree_node_t* node) const
{
    if (node == nullptr) {
        return true;
    }

    if ((!node->m_is_valid_node) && (node != m_root.get())) {
        if ((node->m_left_child == nullptr) || (node->m_right_child == nullptr)) {
            log_err(TABLES, "node=%s invalid node with only one child", node->to_string().c_str());
            dassert_crit(false);
            return false;
        }
    }

    if (node->m_left_child != nullptr) {
        if (node->m_left_child->m_parent_node != node) {
            log_err(TABLES, "node=%s tree structure is corrupted", node->m_left_child->to_string().c_str());
            dassert_crit(false);
            return false;
        }
    }

    if (node->m_right_child != nullptr) {
        if (node->m_right_child->m_parent_node != node) {
            log_err(TABLES, "node=%s tree structure is corrupted", node->m_right_child->to_string().c_str());
            dassert_crit(false);
            return false;
        }
    }

    bool ret_left = sanity_check_child_parent(node->m_left_child.get());
    if (!ret_left) {
        return false;
    }

    bool ret_right = sanity_check_child_parent(node->m_right_child.get());
    if (!ret_right) {
        return false;
    }

    return true;
}

// Implementation of tree_node methods.
template <class data_t>
tree_node<data_t>::tree_node()
    : m_key(0, 0), m_parent_node(nullptr), m_left_child(nullptr), m_right_child(nullptr), m_data(), m_is_valid_node(false)
{
}

template <class data_t>
tree_node<data_t>::tree_node(const lpm_key_t& key, bool is_valid, const data_t& data)
    : m_key(key), m_parent_node(nullptr), m_left_child(nullptr), m_right_child(nullptr), m_data(data), m_is_valid_node(is_valid)
{
}

template <class data_t>
size_t
tree_node<data_t>::get_width() const
{
    return m_key.get_width();
}

template <class data_t>
void
tree_node<data_t>::set_as_child(tree_node* node, bool is_right)
{
    tree_node_sptr& child = is_right ? m_right_child : m_left_child;
    if (node != nullptr) {
        node->m_parent_node = this->shared_from_this();
        child = node->shared_from_this();
    } else {
        child = nullptr;
    }
}

template <class data_t>
bool
tree_node<data_t>::is_leaf() const
{
    return (m_left_child == nullptr) && (m_right_child == nullptr);
}

template <class data_t>
std::string
tree_node<data_t>::to_string() const
{
    std::stringstream s;
    s << "(Key 0x" << m_key.to_string() << "  Width " << get_width() << "valid? " << silicon_one::to_string(m_is_valid_node) << ")";
    return s.str();
}

template <class data_t>
const tree_node<data_t>*
tree_node<data_t>::ancestor() const
{
    const tree_node_t* up = m_parent_node.get();
    while (up != nullptr) {
        if (up->m_is_valid_node) {
            return up;
        }

        up = up->m_parent_node.get();
    }

    return nullptr;
}

template <class data_t>
tree_node<data_t>*
tree_node<data_t>::ancestor()
{
    const tree_node_t& const_tree_node = *this;
    return const_cast<tree_node_t*>(const_tree_node.ancestor());
}

template <class data_t>
const lpm_key_t&
tree_node<data_t>::get_key() const
{
    return m_key;
}

template <class data_t>
const tree_node<data_t>*
tree_node<data_t>::get_left_child() const
{
    return m_left_child.get();
}

template <class data_t>
tree_node<data_t>*
tree_node<data_t>::get_left_child()
{
    return m_left_child.get();
}

template <class data_t>
const tree_node<data_t>*
tree_node<data_t>::get_right_child() const
{
    return m_right_child.get();
}

template <class data_t>
tree_node<data_t>*
tree_node<data_t>::get_right_child()
{
    return m_right_child.get();
}

template <class data_t>
const tree_node<data_t>*
tree_node<data_t>::get_parent_node() const
{
    return m_parent_node.get();
}

template <class data_t>
tree_node<data_t>*
tree_node<data_t>::get_parent_node()
{
    return m_parent_node.get();
}

template <class data_t>
const data_t&
tree_node<data_t>::data() const
{
    return m_data;
}

template <class data_t>
data_t&
tree_node<data_t>::data()
{
    return m_data;
}

template <class data_t>
void
tree_node<data_t>::set_data(const data_t& new_data)
{
    m_data = new_data;
}

template <class data_t>
bool
tree_node<data_t>::is_valid() const
{
    return m_is_valid_node;
}

} // namespace silicon_one

#endif // _LEABA_BINARY_LPM_TREE_H
