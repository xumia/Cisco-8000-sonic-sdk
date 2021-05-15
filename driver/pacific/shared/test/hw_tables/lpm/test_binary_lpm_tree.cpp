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

#include "common/weak_ptr_unsafe.h"
#include "lpm/binary_lpm_tree.h"
#include "gtest/gtest.h"

#include <memory>

using namespace silicon_one;

struct test_struct {
    int data = 0;
};

using test_node = tree_node<test_struct>;
using test_node_sptr = std::shared_ptr<test_node>;
using test_node_wptr = weak_ptr_unsafe<test_node>;

class BinaryTreeTest : public ::testing::Test
{
protected:
    static binary_lpm_tree<test_struct>* s_test_tree;
    static test_node_sptr root;
    /// @brief Returns number of valid or invalid nodes.
    ///
    /// @param[in] valid_nodes Determines wither to count valid or invalid nodes.
    ///
    /// @retun Count of requested nodes.
    static size_t get_number_of_nodes(bool valid_nodes)
    {
        return get_number_of_nodes(root.get(), valid_nodes);
    }

    /// @brief Get total number of nodes, valid and invalid.
    ///
    /// @return Total number of nodes.
    static size_t get_number_of_nodes()
    {
        size_t total_num = 0;
        total_num += get_number_of_nodes(true /* valid_nodes */);
        total_num += get_number_of_nodes(false /* valid_nodes */);
        return total_num;
    }

    static test_node* insert_node(const lpm_key_t& key, const test_struct& test_data)
    {
        log_debug(TABLES, "%s: %s: key=%s/%zu", "Test TCAM Tree", __func__, key.to_string().c_str(), key.get_width());
        test_node* current_node = s_test_tree->find_node(key);
        return s_test_tree->insert_node_to_tree(current_node, key, test_data);
    }

    test_node* find_node(const lpm_key_t& key)
    {
        return s_test_tree->find_node(key);
    }

private:
    static size_t get_number_of_nodes(const test_node* node, bool valid_nodes)
    {
        if (node == nullptr) {
            return 0;
        }

        bool counting_valid_nodes = valid_nodes;
        bool counting_invalid_nodes = !valid_nodes;
        size_t num = (node->is_valid() ? counting_valid_nodes : counting_invalid_nodes);
        num += get_number_of_nodes(node->get_left_child(), valid_nodes);
        num += get_number_of_nodes(node->get_right_child(), valid_nodes);
        return num;
    }
};

class BinaryHardCodedTreeTest : public BinaryTreeTest
{
protected:
    // Ids of stored keysj.
    enum nodeIDs { ID1 = 1, ID2, ID3, ID4, ID5, ID6, ID7, ID8, ID9 };
    // All prefixes that are stored on test tree.
    static const lpm_key_t key1;
    static const lpm_key_t key2;
    static const lpm_key_t key3;
    static const lpm_key_t key4;
    static const lpm_key_t key5;
    static const lpm_key_t key6;
    static const lpm_key_t key7;
    static const lpm_key_t key8;
    static const lpm_key_t key9;
    // Prefixes of invalid nodes.
    static const lpm_key_t invalid_key9;
    static const lpm_key_t invalid_key10;
    // Prefixes not inserted in tree.
    static const lpm_key_t key_not_in_tree1;
    static const lpm_key_t key_not_in_tree2;
    static const lpm_key_t key_not_in_tree3;
    static const lpm_key_t key_not_in_tree4;
    static const lpm_key_t key_not_in_tree5;

    static void SetUpTestCase();
    static void TearDownTestCase();

    static void check_insert(const test_node* node, const lpm_key_t& key, int id)
    {
        ASSERT_NE(node, nullptr);
        EXPECT_TRUE(node->is_valid());
        EXPECT_EQ(key, node->get_key());
        EXPECT_EQ(node->data().data, id);
        if (node != root.get()) {
            const test_node* parent_node = node->get_parent_node();
            const lpm_key_t& parent_key = parent_node->get_key();
            EXPECT_TRUE(is_contained(parent_key, key));
        }
    }

    static void check_leaf(test_node* node)
    {
        const test_node* right_child = node->get_right_child();
        const test_node* left_child = node->get_left_child();
        EXPECT_EQ(right_child, nullptr);
        EXPECT_EQ(left_child, nullptr);
    }
};

class NoPremadeBinaryTreeTest : public BinaryTreeTest
{
protected:
    static void SetUpTestCase();
    static void TearDownTestCase();
};

void
NoPremadeBinaryTreeTest::SetUpTestCase()
{
    // Make empty tree(with only root node).
    s_test_tree = new binary_lpm_tree<test_struct>(std::string("NoPremadeBinaryTreeTest"));
    root = std::const_pointer_cast<test_node>(s_test_tree->get_root()->shared_from_this());
}

void
NoPremadeBinaryTreeTest::TearDownTestCase()
{
    delete s_test_tree;
    s_test_tree = nullptr;
    root = nullptr;
}

// Definitions of static members.
binary_lpm_tree<test_struct>* BinaryTreeTest::s_test_tree(nullptr);

test_node_sptr BinaryTreeTest::root(nullptr);

const lpm_key_t BinaryHardCodedTreeTest::key1(0x1, 4);
const lpm_key_t BinaryHardCodedTreeTest::key2(0x4, 6);
const lpm_key_t BinaryHardCodedTreeTest::key3(0x1f, 8);
const lpm_key_t BinaryHardCodedTreeTest::key4(0x0, 2);
const lpm_key_t BinaryHardCodedTreeTest::key5(0x34, 9);
const lpm_key_t BinaryHardCodedTreeTest::key6(0x36, 9);
const lpm_key_t BinaryHardCodedTreeTest::key7(0x6, 6);
const lpm_key_t BinaryHardCodedTreeTest::key8(0x20, 9);
const lpm_key_t BinaryHardCodedTreeTest::key9(0x3, 5);
// Prefixes of invalid nodes.
const lpm_key_t BinaryHardCodedTreeTest::invalid_key9(key9);
const lpm_key_t BinaryHardCodedTreeTest::invalid_key10(0xd, 7);
const lpm_key_t BinaryHardCodedTreeTest::key_not_in_tree1(0x123, 12);
const lpm_key_t BinaryHardCodedTreeTest::key_not_in_tree2(0x10, 8);
const lpm_key_t BinaryHardCodedTreeTest::key_not_in_tree3(0x1b, 8);
const lpm_key_t BinaryHardCodedTreeTest::key_not_in_tree4(0x18, 8);
const lpm_key_t BinaryHardCodedTreeTest::key_not_in_tree5(0xf, 4);

void
BinaryHardCodedTreeTest::SetUpTestCase()
{
    // Make tree upon all tests will be checked.
    s_test_tree = new binary_lpm_tree<test_struct>(std::string("HardCodedBinaryTreeTest"));
    root = std::const_pointer_cast<test_node>(s_test_tree->get_root()->shared_from_this());

    test_node* out_node;
    test_node* parent_node;
    test_node* parent_parent;
    test_node* parent_left;
    test_node* parent_right;
    test_node* right_child;
    test_node* left_child;

    lpm_key_t parent_key;
    lpm_key_t parent_right_key;
    lpm_key_t parent_left_key;
    lpm_key_t left_child_key;
    lpm_key_t right_child_key;
    lpm_key_t parent_parent_key;

    int parent_right_id;
    int parent_left_id;
    int parent_id;
    int left_child_id;
    int right_child_id;

    test_struct test_data;

    ASSERT_EQ(get_number_of_nodes(), 1U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 0U);

    // Insert first valid node.
    test_data.data = ID1;
    out_node = insert_node(key1, test_data);
    ASSERT_NO_FATAL_FAILURE(check_insert(out_node, key1, ID1));
    check_leaf(out_node);
    parent_node = out_node->get_parent_node();
    ASSERT_EQ(parent_node, root.get());
    ASSERT_EQ(get_number_of_nodes(), 2U); // Inserted node and root node.
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 1U);

    // Insert left child.
    test_data.data = ID2;
    out_node = insert_node(key2, test_data);
    ASSERT_NO_FATAL_FAILURE(check_insert(out_node, key2, ID2));
    check_leaf(out_node);
    // Parent is key1.
    parent_node = out_node->get_parent_node();
    ASSERT_NE(parent_node, nullptr);
    parent_key = parent_node->get_key();
    ASSERT_EQ(parent_key, key1);
    // This is left child.
    parent_left = parent_node->get_left_child();
    parent_right = parent_node->get_right_child();
    ASSERT_EQ(parent_left, out_node);
    ASSERT_EQ(parent_right, nullptr);
    ASSERT_EQ(get_number_of_nodes(), 3U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 2U);

    // Insert node in place that already exist and is valid.
    out_node = insert_node(key2, test_data);
    ASSERT_EQ(out_node, nullptr);

    // Insert right child.
    test_data.data = ID3;
    out_node = insert_node(key3, test_data);
    ASSERT_NO_FATAL_FAILURE(check_insert(out_node, key3, ID3));
    check_leaf(out_node);
    // Parent is key1.
    parent_node = out_node->get_parent_node();
    ASSERT_NE(parent_node, nullptr);
    parent_key = parent_node->get_key();
    ASSERT_EQ(parent_key, key1);
    // This is right child.
    parent_left = parent_node->get_left_child();
    parent_right = parent_node->get_right_child();
    ASSERT_NE(parent_left, nullptr);
    parent_left_key = parent_left->get_key();
    ASSERT_EQ(parent_right, out_node);
    ASSERT_EQ(parent_left_key, key2);
    ASSERT_EQ(get_number_of_nodes(), 4U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 3U);

    // Insert node between root and key1.
    test_data.data = ID4;
    out_node = insert_node(key4, test_data);
    ASSERT_NO_FATAL_FAILURE(check_insert(out_node, key4, ID4));
    parent_node = out_node->get_parent_node();
    ASSERT_EQ(parent_node, root.get());
    right_child = out_node->get_right_child();
    left_child = out_node->get_left_child();
    ASSERT_EQ(right_child, nullptr);
    ASSERT_NE(left_child, nullptr);
    left_child_key = left_child->get_key();
    ASSERT_EQ(left_child_key, key1);
    ASSERT_EQ(get_number_of_nodes(), 5U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 4U);

    // Insert invalid node between key1 and key3. Left child of invalid node is key5, right is key3.
    test_data.data = ID5;
    out_node = insert_node(key5, test_data);
    ASSERT_NO_FATAL_FAILURE(check_insert(out_node, key5, ID5));
    check_leaf(out_node);
    parent_node = out_node->get_parent_node();
    ASSERT_NE(parent_node, nullptr);
    ASSERT_FALSE(parent_node->is_valid());
    parent_key = parent_node->get_key();
    ASSERT_EQ(parent_key, invalid_key9);
    parent_left = parent_node->get_left_child();
    parent_right = parent_node->get_right_child();
    parent_parent = parent_node->get_parent_node();
    ASSERT_EQ(parent_left, out_node);
    ASSERT_NE(parent_right, nullptr);
    parent_right_id = parent_right->data().data;
    ASSERT_EQ(parent_right_id, ID3);
    ASSERT_NE(parent_parent, nullptr);
    int parent_parent_id = parent_parent->data().data;
    ASSERT_EQ(parent_parent_id, ID1);
    ASSERT_EQ(get_number_of_nodes(), 7U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 5U);

    // Insert another invalid node between invalid_key9 and key5. Left child of invalid node is key5, right is key6.
    test_data.data = ID6;
    out_node = insert_node(key6, test_data);
    ASSERT_NO_FATAL_FAILURE(check_insert(out_node, key6, ID6));
    check_leaf(out_node);
    parent_node = out_node->get_parent_node();
    ASSERT_NE(parent_node, nullptr);
    ASSERT_FALSE(parent_node->is_valid());
    parent_key = parent_node->get_key();
    ASSERT_EQ(parent_key, invalid_key10);
    parent_left = parent_node->get_left_child();
    parent_right = parent_node->get_right_child();
    parent_parent = parent_node->get_parent_node();
    ASSERT_EQ(parent_right, out_node);
    ASSERT_NE(parent_left, nullptr);
    parent_left_id = parent_left->data().data;
    ASSERT_EQ(parent_left_id, ID5);
    ASSERT_NE(parent_parent, nullptr);
    parent_parent_key = parent_parent->get_key();
    ASSERT_EQ(parent_parent_key, invalid_key9);
    ASSERT_EQ(get_number_of_nodes(), 9U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 6U);

    // Insert node between invalid_key9 node and invalid_key10 node. Right child of key7 is invalid_key10.
    test_data.data = ID7;
    out_node = insert_node(key7, test_data);
    ASSERT_NO_FATAL_FAILURE(check_insert(out_node, key7, ID7));
    parent_node = out_node->get_parent_node();
    ASSERT_NE(parent_node, nullptr);
    ASSERT_FALSE(parent_node->is_valid());
    parent_key = parent_node->get_key();
    ASSERT_EQ(parent_key, invalid_key9);
    parent_left = parent_node->get_left_child();
    parent_right = parent_node->get_right_child();
    ASSERT_EQ(parent_left, out_node);
    ASSERT_NE(parent_right, nullptr);
    parent_right_id = parent_right->data().data;
    ASSERT_EQ(parent_right_id, ID3);
    right_child = out_node->get_right_child();
    left_child = out_node->get_left_child();
    ASSERT_NE(right_child, nullptr);
    ASSERT_EQ(left_child, nullptr);
    ASSERT_FALSE(right_child->is_valid());
    right_child_key = right_child->get_key();
    ASSERT_EQ(right_child_key, invalid_key10);
    ASSERT_EQ(get_number_of_nodes(), 10U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 7U);

    // Insert node as left child of node key2.
    test_data.data = ID8;
    out_node = insert_node(key8, test_data);
    ASSERT_NO_FATAL_FAILURE(check_insert(out_node, key8, ID8));
    check_leaf(out_node);
    parent_node = out_node->get_parent_node();
    ASSERT_NE(parent_node, nullptr);
    parent_id = parent_node->data().data;
    ASSERT_EQ(parent_id, ID2);
    parent_left = parent_node->get_left_child();
    parent_right = parent_node->get_right_child();
    ASSERT_EQ(parent_left, out_node);
    ASSERT_EQ(parent_right, nullptr);
    ASSERT_EQ(get_number_of_nodes(), 11U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 8U);

    // Insert node in place where invalid_key9 node is.
    test_data.data = ID9;
    out_node = insert_node(key9, test_data);
    ASSERT_NO_FATAL_FAILURE(check_insert(out_node, key9, ID9));
    parent_node = out_node->get_parent_node();
    left_child = out_node->get_left_child();
    right_child = out_node->get_right_child();
    ASSERT_NE(parent_node, nullptr);
    ASSERT_NE(left_child, nullptr);
    ASSERT_NE(right_child, nullptr);
    parent_id = parent_node->data().data;
    left_child_id = left_child->data().data;
    right_child_id = right_child->data().data;
    ASSERT_EQ(parent_id, ID1);
    ASSERT_EQ(left_child_id, ID7);
    ASSERT_EQ(right_child_id, ID3);
    parent_right = parent_node->get_right_child();
    parent_left = parent_node->get_left_child();
    ASSERT_EQ(parent_right, out_node);
    ASSERT_NE(parent_left, nullptr);
    parent_left_id = parent_left->data().data;
    ASSERT_EQ(parent_left_id, ID2);
    ASSERT_EQ(get_number_of_nodes(), 11U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 9U);

    // Check sanity of tree.
    ASSERT_TRUE(s_test_tree->sanity());
}

void
BinaryHardCodedTreeTest::TearDownTestCase()
{
    test_node* out_node;
    test_node* left_child;
    test_node* right_child;
    test_node* right_right_child;
    test_node* right_left_child;
    test_node* left_parent;
    test_node* parent_right;
    test_node* parent_node;

    int left_child_id;
    int right_right_child_id;
    int right_left_child_id;
    int left_parent_id;
    int parent_id;
    int out_node_id;

    ASSERT_EQ(get_number_of_nodes(), 11U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 9U);

    s_test_tree->remove_node_from_tree(key2);
    ASSERT_EQ(get_number_of_nodes(), 10U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 8U);
    out_node = s_test_tree->find_node(key2);
    ASSERT_NE(out_node, nullptr);
    out_node_id = out_node->data().data;
    ASSERT_EQ(out_node_id, ID8);
    out_node = s_test_tree->find_node(key1);
    ASSERT_NE(out_node, nullptr);
    left_child = out_node->get_left_child();
    left_child_id = left_child->data().data;
    ASSERT_EQ(left_child_id, ID8);
    left_parent = left_child->get_parent_node();
    left_parent_id = left_parent->data().data;
    ASSERT_EQ(left_parent_id, ID1);

    s_test_tree->remove_node_from_tree(key9);
    ASSERT_EQ(get_number_of_nodes(), 10U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 7U);
    out_node = s_test_tree->find_node(key9);
    ASSERT_NE(out_node, nullptr);
    out_node_id = out_node->data().data;
    ASSERT_EQ(out_node_id, ID9);
    ASSERT_FALSE(out_node->is_valid());
    out_node = s_test_tree->find_node(key1);
    ASSERT_NE(out_node, nullptr);
    right_child = out_node->get_right_child();
    ASSERT_FALSE(right_child->is_valid());
    right_right_child = right_child->get_right_child();
    right_left_child = right_child->get_left_child();
    ASSERT_NE(right_right_child, nullptr);
    ASSERT_NE(right_left_child, nullptr);
    right_right_child_id = right_right_child->data().data;
    right_left_child_id = right_left_child->data().data;
    ASSERT_EQ(right_right_child_id, ID3);
    ASSERT_EQ(right_left_child_id, ID7);

    s_test_tree->remove_node_from_tree(key6);
    ASSERT_EQ(get_number_of_nodes(), 8U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 6U);
    out_node = s_test_tree->find_node(key6);
    ASSERT_NE(out_node, nullptr);
    out_node_id = out_node->data().data;
    ASSERT_EQ(out_node_id, ID5);
    out_node = s_test_tree->find_node(key5);
    ASSERT_NE(out_node, nullptr);
    parent_node = out_node->get_parent_node();
    ASSERT_NE(parent_node, nullptr);
    parent_right = parent_node->get_right_child();
    ASSERT_EQ(parent_right, out_node);
    parent_id = parent_node->data().data;
    ASSERT_EQ(parent_id, ID7);

    s_test_tree->remove_node_from_tree(key5);
    ASSERT_EQ(get_number_of_nodes(), 7U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 5U);
    out_node = s_test_tree->find_node(key5);
    ASSERT_NE(out_node, nullptr);
    out_node_id = out_node->data().data;
    ASSERT_EQ(out_node_id, ID7);
    out_node = s_test_tree->find_node(key7);
    right_child = out_node->get_right_child();
    ASSERT_EQ(right_child, nullptr);

    s_test_tree->remove_node_from_tree(key1);
    ASSERT_EQ(get_number_of_nodes(), 7U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 4U);
    s_test_tree->remove_node_from_tree(key4);
    ASSERT_EQ(get_number_of_nodes(), 6U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 3U);
    s_test_tree->remove_node_from_tree(key8);
    ASSERT_EQ(get_number_of_nodes(), 4U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 2U);
    s_test_tree->remove_node_from_tree(key7);
    ASSERT_EQ(get_number_of_nodes(), 2U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 1U);
    s_test_tree->remove_node_from_tree(key3);
    ASSERT_EQ(get_number_of_nodes(), 1U);
    ASSERT_EQ(get_number_of_nodes(true /* valid_nodes */), 0U);

    delete s_test_tree;
    s_test_tree = nullptr;
    root = nullptr;
}

TEST_F(BinaryHardCodedTreeTest, TestGetPath)
{
    // Check get_path.
    bool (*clearing_function)(const test_node*) = [](const test_node* node) -> bool {
        if (node->get_key() == key9) {
            return true;
        }

        return false;
    };
    vector_alloc<test_node*> path = s_test_tree->get_path(key6, clearing_function);
    ASSERT_EQ(path.size(), 4U);
    EXPECT_EQ(path[0]->data().data, ID9);
    EXPECT_EQ(path[1]->data().data, ID7);
    EXPECT_EQ(path[2]->get_key(), invalid_key10);
    EXPECT_EQ(path[3]->data().data, ID6);

    clearing_function = [](const test_node* node) -> bool { return false; };
    path = s_test_tree->get_path(root->get_key(), clearing_function);
    ASSERT_EQ(path.size(), 1U);
    ASSERT_EQ(path[0], root.get());

    path = s_test_tree->get_path(invalid_key10, clearing_function);
    ASSERT_EQ(path.size(), 6U);
    EXPECT_EQ(path[0], root.get());
    EXPECT_EQ(path[1]->data().data, ID4);
    EXPECT_EQ(path[2]->data().data, ID1);
    EXPECT_EQ(path[3]->data().data, ID9);
    EXPECT_EQ(path[4]->data().data, ID7);
    EXPECT_EQ(path[5]->get_key(), invalid_key10);

    clearing_function = [](const test_node* node) -> bool {
        if (node->get_key() == key1) {
            return true;
        }
        return false;
    };
    path = s_test_tree->get_path(key_not_in_tree2, clearing_function);
    ASSERT_EQ(path.size(), 3U);
    EXPECT_EQ(path[0]->data().data, ID1);
    EXPECT_EQ(path[1]->data().data, ID2);
    EXPECT_EQ(path[2]->data().data, ID8);

    clearing_function = [](const test_node* node) -> bool {
        if (node->get_key() == key7) {
            return true;
        }
        return false;
    };
    path = s_test_tree->get_path(key_not_in_tree3, clearing_function);
    ASSERT_EQ(path.size(), 3U);
    EXPECT_EQ(path[0]->data().data, ID7);
    EXPECT_EQ(path[1]->get_key(), invalid_key10);
    EXPECT_EQ(path[2]->data().data, ID6);
}

TEST_F(BinaryHardCodedTreeTest, TestFindNode)
{
    test_node* out_node;

    out_node = s_test_tree->find_node(key3);
    ASSERT_NE(out_node, nullptr);
    EXPECT_EQ(out_node->data().data, ID3);

    out_node = s_test_tree->find_node(key8);
    ASSERT_NE(out_node, nullptr);
    EXPECT_EQ(out_node->data().data, ID8);

    out_node = s_test_tree->find_node(key_not_in_tree1);
    ASSERT_NE(out_node, nullptr);
    EXPECT_EQ(out_node->data().data, ID2);

    out_node = s_test_tree->find_node(key_not_in_tree2);
    ASSERT_NE(out_node, nullptr);
    EXPECT_EQ(out_node->data().data, ID8);

    out_node = s_test_tree->find_node(key_not_in_tree3);
    ASSERT_NE(out_node, nullptr);
    EXPECT_EQ(out_node->data().data, ID6);

    out_node = s_test_tree->find_node(key_not_in_tree4);
    ASSERT_NE(out_node, nullptr);
    EXPECT_EQ(out_node->data().data, ID7);
}

TEST_F(BinaryHardCodedTreeTest, TestLongestPrefixMatchLookup)
{
    test_node* out_node;

    out_node = s_test_tree->longest_prefix_match_lookup(key2);
    ASSERT_NE(out_node, nullptr);
    EXPECT_EQ(out_node->data().data, ID2);

    out_node = s_test_tree->longest_prefix_match_lookup(key5);
    ASSERT_NE(out_node, nullptr);
    EXPECT_EQ(out_node->data().data, ID5);

    out_node = s_test_tree->longest_prefix_match_lookup(key_not_in_tree1);
    ASSERT_NE(out_node, nullptr);
    EXPECT_EQ(out_node->data().data, ID2);

    out_node = s_test_tree->longest_prefix_match_lookup(key_not_in_tree2);
    ASSERT_NE(out_node, nullptr);
    EXPECT_EQ(out_node->data().data, ID2);

    out_node = s_test_tree->longest_prefix_match_lookup(key_not_in_tree3);
    ASSERT_NE(out_node, nullptr);
    ASSERT_EQ(out_node->data().data, ID7);

    out_node = s_test_tree->longest_prefix_match_lookup(key_not_in_tree4);
    ASSERT_NE(out_node, nullptr);
    ASSERT_EQ(out_node->data().data, ID7);

    out_node = s_test_tree->longest_prefix_match_lookup(key_not_in_tree5);
    ASSERT_EQ(out_node, nullptr);
}

TEST_F(NoPremadeBinaryTreeTest, KeyZero)
{
    EXPECT_EQ(get_number_of_nodes(true /* valid_nodes */), 0U);

    test_node* node;
    test_node* out_node;

    lpm_key_t key0 = lpm_key_t(0, 0);
    node = find_node(key0);
    ASSERT_EQ(node, root.get());

    test_struct dummy_data;
    out_node = insert_node(key0, dummy_data);
    ASSERT_NE(out_node, nullptr);

    EXPECT_EQ(get_number_of_nodes(), 1U);
    EXPECT_EQ(get_number_of_nodes(true /* valid_nodes */), 1U);
    node = find_node(key0);
    ASSERT_NE(node, nullptr);
    ASSERT_EQ(node->get_key(), key0);
    ASSERT_EQ(node->is_valid(), true);

    out_node = insert_node(key0, dummy_data);
    ASSERT_EQ(out_node, nullptr);

    EXPECT_EQ(get_number_of_nodes(), 1U);
    EXPECT_EQ(get_number_of_nodes(true /* valid_nodes */), 1U);
    node = find_node(key0);
    ASSERT_NE(node, nullptr);
    ASSERT_EQ(node->get_key(), key0);
    ASSERT_EQ(node->is_valid(), true);

    s_test_tree->remove_node_from_tree(key0);
    EXPECT_EQ(get_number_of_nodes(), 1U);
    EXPECT_EQ(get_number_of_nodes(true /* valid_nodes */), 0U);
}
