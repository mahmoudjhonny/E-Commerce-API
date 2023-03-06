const {
  verifyTokenAndAuthorization,
  verifyToken,
  verifyTokenAndAdmin,
} = require("../middleware/verifyToken");
const Cart = require("../models/Cart");

const router = require("express").Router();

//CREATE CART
router.post("/", verifyToken, (req, res) => {
  return Cart.create(req.body)
    .then((cart) => {
      res.status(201).json(cart);
    })
    .catch((err) => {
      res.status(500).json(err);
    });
});

// UPDATE CART
router.put("/:id", verifyTokenAndAuthorization, (req, res) => {
  return Cart.findByIdAndUpdate(
    req.params.id,
    {
      $set: req.body,
    },
    { new: true }
  )
    .then(() => {
      res.status(200).json("Cart Updated Successfuly");
    })
    .catch((err) => {
      res.status(500).json("Cart Updated Failed");
    });
});

// //DELETE CART
router.delete("/:id", verifyTokenAndAuthorization, (req, res) => {
  return Cart.findByIdAndDelete(req.params.id)
    .then(() => {
      res.status(200).json("Product Deleted Successfuly");
    })
    .catch((err) => {
      res.status(500).json("Product Deleted Failed");
    });
});

// GET USER CART
router.get("/find/:userId", verifyTokenAndAuthorization, (req, res) => {
  return Cart.findOne({ userId: req.params.userId })
    .then((cart) => {
      res.status(200).json(cart);
    })
    .catch((err) => {
      res.status(500).json(err);
    });
});

// GET ALL
router.get("/", verifyTokenAndAdmin, (req, res) => {
  return Cart.find()
    .then((carts) => {
      res.status(200).json(carts);
    })
    .catch((err) => {
      res.status(500).json(err);
    });
});

module.exports = router;
